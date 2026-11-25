"""Standard-library unit and socket integration tests for edge-infra-watchdog."""

from __future__ import annotations

import os
import socket
import tempfile
import threading
import unittest

from edge_watchdog.nut_ups import UpsMonitor, parse_nut_status, query_linux_sysfs_battery, query_nut_socket
from edge_watchdog.poe_watchdog import PoeWatchdog, PortTarget
from edge_watchdog.snmp_poe import _is_valid_snmp_response, build_snmpv2c_set_packet, snmp_set_socket


class SnmpPoeTests(unittest.TestCase):
    def test_build_packet_contains_oid_and_community(self) -> None:
        pkt = build_snmpv2c_set_packet("private", "1.3.6.1.2.1.105.1.1.1.3.1.4", 2, request_id=42)
        self.assertEqual(pkt[0], 0x30)
        self.assertIn(b"private", pkt)
        self.assertIn(b"\xa3", pkt)

    def test_validates_snmp_response_error_status(self) -> None:
        ok_resp = b"\x30\x0e\x02\x01\x01\x04\x02ok\xa2\x05\x02\x01\x07\x02\x01\x00"
        err_resp = b"\x30\x0e\x02\x01\x01\x04\x02ok\xa2\x05\x02\x01\x07\x02\x01\x02"
        self.assertTrue(_is_valid_snmp_response(ok_resp))
        self.assertFalse(_is_valid_snmp_response(err_resp))

    def test_snmp_set_socket_roundtrip(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]

        def serve_once() -> None:
            data, addr = srv.recvfrom(4096)
            self.assertIn(b"\xa3", data)
            resp = b"\x30\x10\x02\x01\x01\x04\x07private\xa2\x05\x02\x01\x01\x02\x01\x00"
            srv.sendto(resp, addr)
            srv.close()

        t = threading.Thread(target=serve_once, daemon=True)
        t.start()
        ok = snmp_set_socket("127.0.0.1", "private", "1.3.6.1.2.1.105.1.1.1.3.1.2", 2, port=port, timeout=1.0)
        t.join(timeout=1.0)
        self.assertTrue(ok)


class PoeWatchdogTests(unittest.TestCase):
    def test_stall_reboot_cooldown_escalation_and_recovery(self) -> None:
        now = [1000.0]
        is_up = [False]
        cycles = []
        events = []

        target = PortTarget(name="cam-01", device_ip="10.0.0.10", switch_ip="10.0.0.1", port=4)
        with tempfile.TemporaryDirectory() as tmp:
            state_path = os.path.join(tmp, "poe_state.json")
            wd = PoeWatchdog(
                targets=[target],
                state_file=state_path,
                stall_threshold_sec=180.0,
                min_consecutive_failures=3,
                max_reboots_per_window=2,
                reboot_window_sec=7200.0,
                probe_fn=lambda _: is_up[0],
                switch_alive_fn=lambda _: True,
                power_cycle_fn=lambda t: cycles.append(t.port) or True,
                on_event=events.append,
                clock_fn=lambda: now[0],
            )

            # Failure 1 & 2 below threshold: no reboot yet.
            r1 = wd.check_and_heal()
            now[0] += 60.0
            r2 = wd.check_and_heal()
            self.assertEqual(r1["rebooted"], [])
            self.assertEqual(r2["rebooted"], [])

            # Failure 3 triggers reboot #1.
            now[0] += 60.0
            r3 = wd.check_and_heal()
            self.assertEqual(len(r3["rebooted"]), 1)

            # Failure 4 triggers reboot #2 (max_reboots_per_window = 2).
            now[0] += 60.0
            r4 = wd.check_and_heal()
            self.assertEqual(len(r4["rebooted"]), 1)

            # Failure 5 hits safety guard and escalates once.
            now[0] += 60.0
            r5 = wd.check_and_heal()
            self.assertEqual(r5["escalated"], ["cam-01"])
            self.assertEqual(len(cycles), 2)

            # Target comes back online -> recovery event emitted.
            now[0] += 30.0
            is_up[0] = True
            r6 = wd.check_and_heal()
            self.assertEqual(r6["recovered"], ["cam-01"])
            self.assertEqual(events[-1]["type"], "POE_RECOVERED")


class NutUpsTests(unittest.TestCase):
    def test_parse_nut_status(self) -> None:
        self.assertEqual(parse_nut_status("OL", 100.0), "online")
        self.assertEqual(parse_nut_status("OB DISCHRG", 65.0), "on_battery")
        self.assertEqual(parse_nut_status("OB DISCHRG", 10.0), "low_battery")
        self.assertEqual(parse_nut_status("OL CHRG LB", 90.0), "low_battery")

    def test_query_nut_socket_mock_server(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def serve() -> None:
            conn, _ = srv.accept()
            with conn:
                reader = conn.makefile("r", encoding="utf-8")
                while True:
                    line = reader.readline()
                    if not line:
                        break
                    cmd = line.strip()
                    if cmd == "LIST UPS":
                        conn.sendall(
                            b'BEGIN LIST UPS\nUPS main "Main UPS"\nEND LIST UPS\n'
                        )
                    elif cmd == "LIST VAR main":
                        conn.sendall(
                            b'BEGIN LIST VAR main\n'
                            b'VAR main ups.status "OB DISCHRG"\n'
                            b'VAR main battery.charge "45"\n'
                            b'VAR main battery.runtime "900"\n'
                            b'END LIST VAR main\n'
                        )
                        break
            srv.close()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        data = query_nut_socket("127.0.0.1", port=port, timeout=1.0)
        t.join(timeout=1.0)
        self.assertEqual(data["main"]["battery.charge"], "45")
        self.assertEqual(data["main"]["ups.status"], "OB DISCHRG")

    def test_ups_monitor_state_transitions(self) -> None:
        now = [2000.0]
        shutdown_calls = []
        with tempfile.TemporaryDirectory() as tmp:
            mon = UpsMonitor(
                state_file=os.path.join(tmp, "ups_state.json"),
                on_critical_shutdown=shutdown_calls.append,
                clock_fn=lambda: now[0],
            )
            ev1 = mon.check_and_process_events(
                {"available": True, "state_label": "on_battery", "charge_percent": 80.0, "runtime_minutes": 25}
            )
            self.assertEqual(ev1["type"], "POWER_OUTAGE")

            now[0] += 600.0
            ev2 = mon.check_and_process_events(
                {"available": True, "state_label": "low_battery", "charge_percent": 9.0, "runtime_minutes": 2}
            )
            self.assertEqual(ev2["type"], "CRITICAL_POWER_EXHAUSTION")
            self.assertEqual(len(shutdown_calls), 1)

            now[0] += 180.0
            ev3 = mon.check_and_process_events(
                {"available": True, "state_label": "online", "charge_percent": 20.0, "runtime_minutes": 15}
            )
            self.assertEqual(ev3["type"], "POWER_RESTORED")
            self.assertEqual(ev3["duration_minutes"], 13)

    def test_sysfs_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bat = os.path.join(tmp, "BAT0")
            os.makedirs(bat)
            for name, val in [("type", "Battery\n"), ("status", "Discharging\n"), ("capacity", "55\n")]:
                with open(os.path.join(bat, name), "w", encoding="utf-8") as fh:
                    fh.write(val)
            res = query_linux_sysfs_battery(tmp)
            self.assertEqual(res["ups.status"], "OB")
            self.assertEqual(res["battery.charge"], "55")


if __name__ == "__main__":
    unittest.main()
