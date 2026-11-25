# edge-infra-watchdog

Zero-dependency Python 3 library and CLI for autonomous edge infrastructure self-healing:

1. **PoE Watchdog (`edge_watchdog.poe_watchdog`, `edge_watchdog.snmp_poe`)**
   - Monitors downstream IP/RTSP devices and power-cycles hung PoE switch ports via **raw UDP SNMPv2c (`RFC 3621` `pethPsePortAdminEnable`)**, `snmpset` fallback, or SSH CLI (MikroTik RouterOS / Keenetic).
   - Verifies switch reachability before acting so a switch outage never triggers spurious port resets.
   - Sliding-window reboot safety guard (`max_reboots_per_window` / `reboot_window_sec`) with atomic JSON state persistence and `CRITICAL_HARDWARE_DEFECT` escalation.

2. **NUT UPS Monitor (`edge_watchdog.nut_ups`)**
   - Queries Network UPS Tools (`upsd`) directly over raw TCP (`LIST UPS` / `LIST VAR`), with automatic fallbacks to `upsc` CLI and Linux `/sys/class/power_supply`.
   - Tracks `POWER_OUTAGE`, `POWER_RESTORED`, and `CRITICAL_POWER_EXHAUSTION` state transitions with an optional callback for safe OS shutdown.

Extracted from a production monitoring agent (`cctv-service`) as a clean, dependency-free open-source package (`stdlib` only).

## Run Tests

```bash
python -m unittest discover -s tests -v
```

## Quick Usage

```python
from edge_watchdog import PoeWatchdog, PortTarget, UpsMonitor

targets = [
    PortTarget(
        name="cam-gate-01",
        device_ip="192.168.10.21",
        switch_ip="192.168.10.2",
        port=4,
        snmp_community="private",
    )
]

watchdog = PoeWatchdog(targets=targets, state_file="/var/lib/edge-watchdog/poe.json")
report = watchdog.check_and_heal()

ups = UpsMonitor(host="127.0.0.1", port=3493, state_file="/var/lib/edge-watchdog/ups.json")
event = ups.check_and_process_events()
```

CLI helpers:

```bash
python -m edge_watchdog ups-status --host 127.0.0.1 --port 3493
python -m edge_watchdog snmp-poe-set --switch-ip 192.168.10.2 --port 4 --state off
```

## License

MIT.
