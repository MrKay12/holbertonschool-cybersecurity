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


def get_banner(ip: str, port: int) -> str:
    """Grab the banner of the service running on a TCP port.

    Args:
        ip: Target IP address or hostname.
        port: TCP port to probe.

    Returns:
        The banner without surrounding whitespace, or "Unknown".
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(2)
        try:
            sock.connect((ip, port))
            try:
                data = sock.recv(1024)
            except socket.timeout:
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                data = sock.recv(1024)
            banner = data.decode(errors="ignore").strip()
            return banner if banner else "Unknown"
        except OSError:
            return "Unknown"


def main():
    """Entry point of NetProbe."""
    print(f"NetProbe v{VERSION} initialized...")
    print(get_banner("scanme.nmap.org", 22))


if __name__ == "__main__":
    main()
