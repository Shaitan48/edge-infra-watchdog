"""Zero-dependency PoE watchdog and NUT UPS monitor for edge infrastructure."""

from .nut_ups import UpsMonitor, parse_nut_status, query_linux_sysfs_battery, query_nut_cli, query_nut_socket
from .poe_watchdog import PoeWatchdog, PortTarget
from .snmp_poe import build_snmpv2c_set_packet, snmp_set_poe, snmp_set_socket

__all__ = [
    "PoeWatchdog",
    "PortTarget",
    "UpsMonitor",
    "build_snmpv2c_set_packet",
    "parse_nut_status",
    "query_linux_sysfs_battery",
    "query_nut_cli",
    "query_nut_socket",
    "snmp_set_poe",
    "snmp_set_socket",
]
