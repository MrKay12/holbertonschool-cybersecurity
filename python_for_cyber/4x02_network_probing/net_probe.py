#!/usr/bin/env python3
"""NetProbe: a simple network probing tool."""

import socket
from concurrent.futures import ThreadPoolExecutor

VERSION = "1.0"


def check_port(ip: str, port: int) -> bool:
    """Check if a TCP port is open on a target.

    Args:
        ip: Target IP address or hostname.
        port: TCP port to test.

    Returns:
        True if the TCP handshake succeeds, False otherwise.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        try:
            sock.connect((ip, port))
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False


def ping_sweep(subnet: str) -> list:
    """Find live hosts in a /24 subnet by testing TCP port 80.

    Args:
        subnet: The first three octets of the network (e.g. "192.168.1").

    Returns:
        A list of IPs with port 80 open, in ascending order.
    """
    ips = [f"{subnet}.{host}" for host in range(1, 255)]
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(lambda ip: check_port(ip, 80), ips)
    return [ip for ip, is_open in zip(ips, results) if is_open]


def main():
    """Entry point of NetProbe."""
    print(f"NetProbe v{VERSION} initialized...")
    print(ping_sweep("192.168.1"))


if __name__ == "__main__":
    main()
