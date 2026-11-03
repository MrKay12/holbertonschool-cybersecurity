#!/usr/bin/env python3
"""NetProbe: a simple network probing tool."""

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

VERSION = "1.0"
MAX_THREADS = 50


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
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
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
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = sock.recv(1024)
            banner = data.decode(errors="ignore").strip()
            return banner if banner else "Unknown"
        except OSError:
            return "Unknown"


def scan_one_port(ip: str, port: int):
    """Scan a single port and grab its banner if it is open.

    Args:
        ip: Target IP address or hostname.
        port: TCP port to scan.

    Returns:
        A dict {'port': port, 'service': banner} if open, None otherwise.
    """
    if check_port(ip, port):
        return {'port': port, 'service': get_banner(ip, port)}
    return None


def scan_ports(ip: str, start_port: int, end_port: int) -> list:
    """Scan a range of TCP ports with a thread pool and grab their banners.

    Args:
        ip: Target IP address or hostname.
        start_port: First port to scan (included).
        end_port: Last port to scan (included).

    Returns:
        A list of dicts like {'port': 22, 'service': 'SSH-2.0-OpenSSH'},
        sorted by port number.
    """
    print(f"Scanning {ip} from {start_port} to {end_port}...")
    open_ports = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [executor.submit(scan_one_port, ip, port)
                   for port in range(start_port, end_port + 1)]
        for future in as_completed(futures):
            result = future.result()
            if result:
                print(f"[+] Port {result['port']} Open: {result['service']}")
                open_ports.append(result)
    return sorted(open_ports, key=lambda entry: entry['port'])


def main():
    """Entry point of NetProbe."""
    print(f"NetProbe v{VERSION} initialized...")
    start = time.perf_counter()
    scan_ports("scanme.nmap.org", 1, 1024)
    elapsed = time.perf_counter() - start
    print(f"Scan completed in {elapsed:.2f} seconds")


if __name__ == "__main__":
    main()
