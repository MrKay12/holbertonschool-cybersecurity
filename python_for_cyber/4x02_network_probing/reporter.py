#!/usr/bin/env python3
"""Reporting logic for NetProbe: console and JSON output."""

import json

from utils import check_vulnerability, guess_service


def print_infos(ip, ports_analysis: list) -> None:
    """Print informations after analysis

    Args:
        ip: Target IP
        ports_analysis: extracted ports
    """
    if ports_analysis:
        for port in ports_analysis:
            if port:
                print(
                    f"[+] Port {port['port']}: "
                    f"{guess_service(ip, port['port'])} "
                    f"({port['service']})"
                    f"{check_vulnerability(port['service'])}"
                )
    else:
        print("No Port Discovered")


def generate_json_report(ip: str,
                         domain: str,
                         filename: str,
                         ports_analytics: list) -> None:
    """Generate human-readable report with JSON format

    Args:
        filename: path or direct filename to write
        ports_analytics: data to write
    """
    infos = f"{ip} ({domain})"
    ports_analytics.insert(0, {'target': infos})
    to_json_str_data = json.dumps(ports_analytics, indent=2)

    with open(filename, "w") as file:
        file.write(to_json_str_data)
        file.write('\n')
