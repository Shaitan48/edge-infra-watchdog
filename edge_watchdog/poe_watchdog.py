"""Autonomous PoE port watchdog with sliding-window cooldown and escalation."""

from __future__ import annotations

import json
import logging
import os
import socket
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from .snmp_poe import snmp_set_poe

logger = logging.getLogger(__name__)


@dataclass
class PortTarget:
    """Single monitored PoE device attached to a managed switch port."""

    name: str
    device_ip: str
    switch_ip: str
    port: int
    probe_port: int = 554
    protocol: str = "snmp"
    snmp_community: str = "private"
    switch_user: str = "admin"
    switch_password: str = ""
    interface_name: str = "FastEthernet0"


def check_tcp_alive(host: str, port: int = 554, timeout: float = 1.5) -> bool:
    """Return True if a TCP connection to host:port succeeds."""
    if not host:
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def is_switch_reachable(
    host: str,
    ports: Tuple[int, ...] = (80, 443, 22, 23, 161, 554),
    timeout: float = 1.5,
) -> bool:
    """Check whether the switch itself responds on management TCP ports or ICMP."""
    if not host:
        return False
    for port in ports:
        if check_tcp_alive(host, port, timeout=timeout):
            return True
    try:
        ping_cmd = (
            ["ping", "-n", "1", "-w", "1000", host]
            if os.name == "nt"
            else ["ping", "-c", "1", "-W", "1", host]
        )
        res = subprocess.run(
            ping_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2.5
        )
        return res.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _exec_ssh_command(user: str, host: str, command: str, timeout: float = 10.0) -> bool:
    try:
        res = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=4", f"{user}@{host}", command],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        return res.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def default_power_cycle(target: PortTarget, pause_sec: float = 5.0) -> bool:
    """Power-cycle a switch port using SNMP RFC 3621 or SSH CLI."""
    proto = target.protocol.lower().strip()
    if "keenetic" in proto:
        cmd = f"interface {target.interface_name}/{target.port} power cycle"
        return _exec_ssh_command(target.switch_user, target.switch_ip, cmd)
    if "mikrotik" in proto or "routeros" in proto:
        delay = max(1, int(round(pause_sec)))
        cmd = (
            f"/interface ethernet poe set {target.port} poe-out=off; "
            f":delay {delay}s; "
            f"/interface ethernet poe set {target.port} poe-out=auto"
        )
        return _exec_ssh_command(target.switch_user, target.switch_ip, cmd, timeout=delay + 8.0)

    off_ok = snmp_set_poe(target.switch_ip, target.snmp_community, target.port, enable=False)
    time.sleep(pause_sec)
    on_ok = snmp_set_poe(target.switch_ip, target.snmp_community, target.port, enable=True)
    return on_ok or off_ok


class PoeWatchdog:
    """Monitors downstream devices and power-cycles hung PoE ports safely."""

    def __init__(
        self,
        targets: List[PortTarget],
        state_file: str,
        stall_threshold_sec: float = 180.0,
        min_consecutive_failures: int = 3,
        max_reboots_per_window: int = 2,
        reboot_window_sec: float = 7200.0,
        cycle_pause_sec: float = 5.0,
        probe_fn: Optional[Callable[[PortTarget], bool]] = None,
        switch_alive_fn: Optional[Callable[[str], bool]] = None,
        power_cycle_fn: Optional[Callable[[PortTarget], bool]] = None,
        on_event: Optional[Callable[[Dict[str, Any]], None]] = None,
        clock_fn: Optional[Callable[[], float]] = None,
    ) -> None:
        self.targets = targets
        self.state_file = os.path.abspath(state_file)
        self.stall_threshold_sec = stall_threshold_sec
        self.min_consecutive_failures = min_consecutive_failures
        self.max_reboots_per_window = max_reboots_per_window
        self.reboot_window_sec = reboot_window_sec
        self.cycle_pause_sec = cycle_pause_sec
        self.probe_fn = probe_fn or (lambda t: check_tcp_alive(t.device_ip, t.probe_port))
        self.switch_alive_fn = switch_alive_fn or is_switch_reachable
        self.power_cycle_fn = power_cycle_fn or (lambda t: default_power_cycle(t, self.cycle_pause_sec))
        self.on_event = on_event
        self.clock_fn = clock_fn or time.time
        self.state = self._load_state()

    def _load_state(self) -> Dict[str, Any]:
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                    if isinstance(data, dict) and isinstance(data.get("ports"), dict):
                        return data
            except (OSError, ValueError) as exc:
                logger.warning("Failed to load PoE watchdog state: %s", exc)
        return {"ports": {}}

    def _save_state(self) -> None:
        os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
        tmp_path = f"{self.state_file}.tmp_{os.getpid()}"
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(self.state, fh, ensure_ascii=False, indent=2)
        os.replace(tmp_path, self.state_file)

    def _emit(self, event: Dict[str, Any]) -> None:
        if self.on_event:
            self.on_event(event)

    def clean_expired_reboots(self, now_ts: float) -> None:
        cutoff = now_ts - self.reboot_window_sec
        for info in self.state["ports"].values():
            reboots = [t for t in info.get("reboots", []) if t >= cutoff]
            info["reboots"] = reboots
            if not reboots and not info.get("consecutive_failures", 0):
                info["escalated"] = False

    def check_and_heal(self) -> Dict[str, Any]:
        """Run one inspection cycle across all configured PoE targets."""
        now_ts = self.clock_fn()
        self.clean_expired_reboots(now_ts)

        results: Dict[str, Any] = {
            "checked": len(self.targets),
            "rebooted": [],
            "escalated": [],
            "recovered": [],
            "skipped": [],
        }

        for target in self.targets:
            port_key = f"{target.switch_ip}:{target.port}"
            port_state = self.state["ports"].setdefault(
                port_key,
                {
                    "reboots": [],
                    "first_failure_time": 0.0,
                    "consecutive_failures": 0,
                    "escalated": False,
                    "pending_recovery": False,
                    "last_reboot": 0.0,
                },
            )

            if self.probe_fn(target):
                if port_state.get("pending_recovery") or port_state.get("consecutive_failures", 0) > 0:
                    recovery_sec = max(1, int(now_ts - port_state.get("last_reboot", now_ts)))
                    port_state["pending_recovery"] = False
                    port_state["consecutive_failures"] = 0
                    port_state["first_failure_time"] = 0.0
                    port_state["escalated"] = False
                    results["recovered"].append(target.name)
                    self._emit(
                        {
                            "type": "POE_RECOVERED",
                            "severity": "info",
                            "target": target.name,
                            "port": target.port,
                            "switch_ip": target.switch_ip,
                            "recovery_seconds": recovery_sec,
                            "timestamp": now_ts,
                        }
                    )
                continue

            if port_state["first_failure_time"] == 0.0:
                port_state["first_failure_time"] = now_ts
                port_state["consecutive_failures"] = 1
            else:
                port_state["consecutive_failures"] += 1

            stall_duration = now_ts - port_state["first_failure_time"]
            if (
                stall_duration < self.stall_threshold_sec
                and port_state["consecutive_failures"] < self.min_consecutive_failures
            ):
                results["skipped"].append({"target": target.name, "reason": "below_stall_threshold"})
                continue

            if not self.switch_alive_fn(target.switch_ip):
                results["skipped"].append({"target": target.name, "reason": "switch_unreachable"})
                continue

            recent_reboots = port_state.get("reboots", [])
            if len(recent_reboots) >= self.max_reboots_per_window:
                if not port_state.get("escalated"):
                    port_state["escalated"] = True
                    results["escalated"].append(target.name)
                    self._emit(
                        {
                            "type": "CRITICAL_HARDWARE_DEFECT",
                            "severity": "critical",
                            "target": target.name,
                            "port": target.port,
                            "switch_ip": target.switch_ip,
                            "reboots_in_window": len(recent_reboots),
                            "timestamp": now_ts,
                        }
                    )
                continue

            cycle_ok = self.power_cycle_fn(target)
            port_state["reboots"].append(now_ts)
            port_state["last_reboot"] = now_ts
            port_state["pending_recovery"] = True
            results["rebooted"].append(
                {
                    "target": target.name,
                    "port": target.port,
                    "switch_ip": target.switch_ip,
                    "protocol": target.protocol,
                    "cycle_ok": cycle_ok,
                }
            )
            self._emit(
                {
                    "type": "POE_POWER_CYCLED",
                    "severity": "warning",
                    "target": target.name,
                    "port": target.port,
                    "switch_ip": target.switch_ip,
                    "cycle_ok": cycle_ok,
                    "timestamp": now_ts,
                }
            )

        self._save_state()
        return results
