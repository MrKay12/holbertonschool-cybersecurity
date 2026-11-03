#!/usr/bin/env python3
"""NetProbe: CLI entry point for the network probing tool."""

import argparse
import socket as skt

import scanner
from reporter import generate_json_report


def main() -> None:
    """Program Entry Point"""
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target",
                        help="Target IP",
                        required=True)
    parser.add_argument("-p", "--ports",
                        required=True,
                        help="Port range to scan")
    parser.add_argument("-o", "--output",
                        help="Generate report to file")
    parser.add_argument("-d", "--delay", type=float,
                        help="Set a delay between ports analysis")
    parser.add_argument("-r", "--random", action="store_true",
                        help="Shuffle the list of ports")
    parser.add_argument("-i", "--interface",
                        help="Interface to use (for binding)")

    args = parser.parse_args()
    sep_port = args.ports.find('-')

    ip = args.target
    lower_port = int(args.ports[:sep_port])
    upper_port = int(args.ports[sep_port + 1:])

    delay = 0.0
    if args.delay:
        delay = float(args.delay)

    if args.random:
        shuffle_set = True
    else:
        shuffle_set = False

    if args.interface:
        scanner.INTERFACE = args.interface
        print(f"[INFO] Scanning from source: {scanner.INTERFACE}")

    ports = scanner.scan_ports(ip,
                               lower_port,
                               upper_port,
                               delay=delay,
                               shuffle=shuffle_set)

    try:
        domain = skt.gethostbyaddr(ip)[0]
    except (skt.herror, skt.gaierror, OSError):
        domain = "Unknown"
    print(f"Target: {ip} ({domain})")

    if args.output:
        generate_json_report(ip,
                             domain,
                             args.output,
                             ports)


if __name__ == '__main__':
    main()