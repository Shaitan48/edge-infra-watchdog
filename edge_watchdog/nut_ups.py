"""Zero-dependency UPS and mains power monitor via NUT TCP protocol, upsc CLI, and Linux sysfs."""

from __future__ import annotations

import json
import logging
import os
import shutil
import socket
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


def query_nut_socket(
    host: str = "127.0.0.1", port: int = 3493, timeout: float = 0.5
) -> Dict[str, Dict[str, str]]:
    """Query Network UPS Tools (upsd) over raw TCP socket."""
    result: Dict[str, Dict[str, str]] = {}
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            reader = sock.makefile("r", encoding="utf-8", errors="replace")

            sock.sendall(b"LIST UPS\n")
            ups_names: List[str] = []
            while True:
                line = reader.readline()
                if not line:
                    break
                line = line.strip()
                if line.startswith("BEGIN LIST UPS"):
                    continue
                if line.startswith("END LIST UPS"):
                    break
                parts = line.split(maxsplit=2)
                if len(parts) >= 2 and parts[0] == "UPS":
                    ups_names.append(parts[1])

            for uname in ups_names:
                result[uname] = {}
                sock.sendall(f"LIST VAR {uname}\n".encode("utf-8"))
                while True:
                    vline = reader.readline()
                    if not vline:
                        break
                    vline = vline.strip()
                    if vline.startswith(f"BEGIN LIST VAR {uname}"):
                        continue
                    if vline.startswith(f"END LIST VAR {uname}"):
                        break
                    vparts = vline.split(maxsplit=3)
                    if len(vparts) >= 4 and vparts[0] == "VAR":
                        result[uname][vparts[2]] = vparts[3].strip('"')
    except OSError as exc:
        logger.debug("NUT socket query failed (%s:%d): %s", host, port, exc)
    return result


def query_nut_cli(ups_name: Optional[str] = None) -> Dict[str, str]:
    """Fallback query using the `upsc` CLI utility."""
    vars_map: Dict[str, str] = {}
    if not shutil.which("upsc"):
        return vars_map
    try:
        target = ups_name
        if not target:
            proc_l = subprocess.run(
                ["upsc", "-l"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2
            )
            if proc_l.returncode == 0:
                names = [n.strip() for n in proc_l.stdout.splitlines() if n.strip()]
                target = names[0] if names else None
        if not target:
            return vars_map
        proc = subprocess.run(
            ["upsc", target], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2
        )
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    vars_map[k.strip()] = v.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("upsc CLI query failed: %s", exc)
    return vars_map


def query_linux_sysfs_battery(power_supply_dir: str = "/sys/class/power_supply") -> Dict[str, str]:
    """Fallback query for Linux sysfs battery/UPS devices."""
    vars_map: Dict[str, str] = {}
    if not os.path.isdir(power_supply_dir):
        return vars_map
    try:
        for entry in os.listdir(power_supply_dir):
            epath = os.path.join(power_supply_dir, entry)
            type_file = os.path.join(epath, "type")
            if not os.path.exists(type_file):
                continue
            with open(type_file, "r", encoding="utf-8") as tf:
                tval = tf.read().strip().upper()
            if tval not in ("UPS", "BATTERY"):
                continue

            def _read_prop(fname: str) -> str:
                p = os.path.join(epath, fname)
                if os.path.exists(p):
                    with open(p, "r", encoding="utf-8") as fh:
                        return fh.read().strip()
                return ""

            st = _read_prop("status").upper()
            nut_status = "OL"
            if "DISCHARG" in st:
                nut_status = "OB"
            elif "CHARG" in st:
                nut_status = "OL CHRG"

            vars_map["ups.status"] = nut_status
            if cap := _read_prop("capacity"):
                vars_map["battery.charge"] = cap
            if model := _read_prop("model_name"):
                vars_map["ups.model"] = model
            if mfr := _read_prop("manufacturer"):
                vars_map["ups.mfr"] = mfr
            break
    except OSError as exc:
        logger.debug("sysfs power_supply read failed: %s", exc)
    return vars_map


def parse_nut_status(raw_status: str, charge: float, low_battery_threshold: float = 12.0) -> str:
    """Normalize NUT ups.status string into online, on_battery, low_battery, charging, or unknown."""
    st = (raw_status or "").upper()
    if "LB" in st or (0.0 < charge <= low_battery_threshold and "OB" in st):
        return "low_battery"
    if "OB" in st:
        return "on_battery"
    if "OL" in st:
        return "online"
    if "CHRG" in st:
        return "charging"
    return "unknown"


def _parse_float(raw: Optional[str], default: Optional[float] = None) -> Optional[float]:
    if raw is None:
        return default
    try:
        return float(raw)
    except (ValueError, TypeError):
        return default


class UpsMonitor:
    """Monitors UPS state transitions and emits power outage/restoration/exhaustion events."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 3493,
        ups_name: str = "",
        state_file: str = "ups_state.json",
        cache_ttl_sec: float = 15.0,
        low_battery_threshold: float = 12.0,
        on_critical_shutdown: Optional[Callable[[Dict[str, Any]], None]] = None,
        clock_fn: Optional[Callable[[], float]] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.ups_name = ups_name
        self.state_file = os.path.abspath(state_file)
        self.cache_ttl_sec = cache_ttl_sec
        self.low_battery_threshold = low_battery_threshold
        self.on_critical_shutdown = on_critical_shutdown
        self.clock_fn = clock_fn or time.time
        self._cached_status: Optional[Dict[str, Any]] = None
        self._cache_expires = 0.0

    def get_status(self, force: bool = False) -> Dict[str, Any]:
        """Collect UPS metrics via NUT socket -> upsc CLI -> Linux sysfs with short caching."""
        now_ts = self.clock_fn()
        if not force and self._cached_status and now_ts < self._cache_expires:
            return self._cached_status

        raw_vars: Dict[str, str] = {}
        target_name = self.ups_name

        socket_data = query_nut_socket(self.host, self.port)
        if socket_data:
            if target_name and target_name in socket_data:
                raw_vars = socket_data[target_name]
            else:
                target_name = next(iter(socket_data.keys()))
                raw_vars = socket_data[target_name]

        if not raw_vars:
            raw_vars = query_nut_cli(self.ups_name or None)
            if raw_vars and not target_name:
                target_name = self.ups_name or "ups"

        if not raw_vars:
            raw_vars = query_linux_sysfs_battery()
            if raw_vars and not target_name:
                target_name = "sysfs-battery"

        if not raw_vars:
            res = {
                "available": False,
                "name": None,
                "status": "UNAVAILABLE",
                "state_label": "unknown",
                "charge_percent": None,
                "runtime_seconds": None,
                "runtime_minutes": None,
                "input_voltage": None,
                "output_voltage": None,
                "battery_voltage": None,
                "model": "Unknown",
                "mfr": "Generic",
                "timestamp": now_ts,
                "details": {},
            }
            self._cached_status = res
            self._cache_expires = now_ts + self.cache_ttl_sec
            return res

        status_str = raw_vars.get("ups.status", "OL").strip()
        charge = _parse_float(raw_vars.get("battery.charge"), 100.0)
        assert charge is not None
        runtime_f = _parse_float(raw_vars.get("battery.runtime"))
        runtime_sec = int(runtime_f) if runtime_f is not None else None
        runtime_min = int(round(runtime_sec / 60)) if runtime_sec is not None else None

        res = {
            "available": True,
            "name": target_name or "ups",
            "status": status_str,
            "state_label": parse_nut_status(status_str, charge, self.low_battery_threshold),
            "charge_percent": charge,
            "runtime_seconds": runtime_sec,
            "runtime_minutes": runtime_min,
            "input_voltage": _parse_float(raw_vars.get("input.voltage")),
            "output_voltage": _parse_float(raw_vars.get("output.voltage")),
            "battery_voltage": _parse_float(raw_vars.get("battery.voltage")),
            "model": raw_vars.get("ups.model") or raw_vars.get("device.model") or "Smart-UPS",
            "mfr": raw_vars.get("ups.mfr") or raw_vars.get("device.mfr") or "APC/NUT",
            "timestamp": now_ts,
            "details": raw_vars,
        }
        self._cached_status = res
        self._cache_expires = now_ts + self.cache_ttl_sec
        return res

    def _load_persisted_state(self) -> Dict[str, Any]:
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                    if isinstance(data, dict):
                        return data
            except (OSError, ValueError):
                pass
        return {"prev_state_label": "online", "outage_start": None, "last_critical_ts": 0.0}

    def _save_persisted_state(self, state: Dict[str, Any]) -> None:
        os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
        tmp_path = f"{self.state_file}.tmp_{os.getpid()}"
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2, ensure_ascii=False)
        os.replace(tmp_path, self.state_file)

    def check_and_process_events(
        self, current_status: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """Detect mains outage, restoration, or critical battery exhaustion."""
        if current_status is None:
            current_status = self.get_status()
        if not current_status.get("available"):
            return None

        persisted = self._load_persisted_state()
        prev_label = persisted.get("prev_state_label", "online")
        outage_start = persisted.get("outage_start")
        cur_label = current_status.get("state_label", "online")
        charge = float(current_status.get("charge_percent") or 100.0)
        runtime_min = current_status.get("runtime_minutes") or 0
        now_ts = self.clock_fn()

        event: Optional[Dict[str, Any]] = None

        if cur_label == "low_battery" or (
            cur_label == "on_battery" and charge <= self.low_battery_threshold
        ):
            last_crit = float(persisted.get("last_critical_ts") or 0.0)
            if now_ts - last_crit > 300.0:
                persisted["last_critical_ts"] = now_ts
                event = {
                    "type": "CRITICAL_POWER_EXHAUSTION",
                    "severity": "critical",
                    "charge": charge,
                    "runtime_minutes": runtime_min,
                    "timestamp": now_ts,
                }
                if self.on_critical_shutdown:
                    self.on_critical_shutdown(event)
        elif prev_label == "online" and cur_label == "on_battery":
            persisted["outage_start"] = now_ts
            event = {
                "type": "POWER_OUTAGE",
                "severity": "warning",
                "charge": charge,
                "runtime_minutes": runtime_min,
                "timestamp": now_ts,
            }
        elif prev_label in ("on_battery", "low_battery") and cur_label in ("online", "charging"):
            duration_min = int((now_ts - (outage_start or now_ts)) / 60.0)
            persisted["outage_start"] = None
            event = {
                "type": "POWER_RESTORED",
                "severity": "info",
                "duration_minutes": duration_min,
                "charge": charge,
                "timestamp": now_ts,
            }

        persisted["prev_state_label"] = cur_label
        self._save_persisted_state(persisted)
        return event
