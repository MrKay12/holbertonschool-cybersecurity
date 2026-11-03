#!/usr/bin/env python3
"""NetProbe: a simple network probing tool."""

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

VERSION = "1.0"
MAX_THREADS = 50
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Alt",
}


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


def guess_service(port: int) -> str:
    """Guess the service name from a well-known port number.

    Args:
        port: TCP port number.

    Returns:
        The usual service name for this port, or "Unknown".
    """
    return COMMON_PORTS.get(port, "Unknown")


def get_service_info(ip: str, port: int) -> str:
    """Identify a service by its banner, or guess it from the port.

    Args:
        ip: Target IP address or hostname.
        port: TCP port to identify.

    Returns:
        The banner if one is received, otherwise the guessed service
        name followed by "(Guessed)", or "Unknown".
    """
    banner = get_banner(ip, port)
    if banner and banner != "Unknown":
        return banner
    service = guess_service(port)
    if service == "Unknown":
        return "Unknown"
    return f"{service} (Guessed)"


def scan_one_port(ip: str, port: int):
    """Scan a single port and identify its service if it is open.

    Args:
        ip: Target IP address or hostname.
        port: TCP port to scan.

    Returns:
        A dict {'port': port, 'service': info} if open, None otherwise.
    """
    if check_port(ip, port):
        return {'port': port, 'service': get_service_info(ip, port)}
    return None


def scan_ports(ip: str, start_port: int, end_port: int) -> list:
    """Scan a range of TCP ports with a thread pool and identify services.

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
    print(get_service_info("192.168.1.1", 80))


if __name__ == "__main__":
    main()
