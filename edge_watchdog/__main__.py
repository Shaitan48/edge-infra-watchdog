"""Minimal CLI entry point for edge-infra-watchdog."""

from __future__ import annotations

import argparse
import json
import sys

from .nut_ups import UpsMonitor
from .snmp_poe import snmp_set_poe


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="edge-watchdog")
    sub = parser.add_subparsers(dest="cmd", required=True)

    ups_p = sub.add_parser("ups-status", help="Query NUT UPS status as JSON")
    ups_p.add_argument("--host", default="127.0.0.1")
    ups_p.add_argument("--port", type=int, default=3493)
    ups_p.add_argument("--ups", default="")

    poe_p = sub.add_parser("snmp-poe-set", help="Set PoE admin state via RFC 3621 SNMPv2c")
    poe_p.add_argument("--switch-ip", required=True)
    poe_p.add_argument("--port", type=int, required=True)
    poe_p.add_argument("--community", default="private")
    poe_p.add_argument("--state", choices=["on", "off"], required=True)

    args = parser.parse_args(argv)
    if args.cmd == "ups-status":
        mon = UpsMonitor(host=args.host, port=args.port, ups_name=args.ups)
        print(json.dumps(mon.get_status(force=True), indent=2))
        return 0

    ok = snmp_set_poe(
        args.switch_ip,
        args.community,
        args.port,
        enable=(args.state == "on"),
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
