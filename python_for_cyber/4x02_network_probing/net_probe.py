#!/usr/bin/env python3
"""NetProbe: a simple network probing tool."""

import argparse
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

VERSION = "1.0"
MAX_THREADS = 50
DELAY = 0
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
VULNERABLE_SIGNATURES = [
    "vsftpd 2.3.4",
    "apache 2.2.8",
    "apache/2.2.8",
    "openssh_7.2p1",
    "proftpd 1.3.3c",
    "unrealircd 3.2.8.1",
]


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


def check_vulnerability(banner: str) -> str:
    """Flag a banner that matches a known vulnerable version.

    Args:
        banner: The service banner to check.

    Returns:
        "[VULNERABLE]" if a known bad signature is found, "" otherwise.
    """
    banner_lower = banner.lower()
    for signature in VULNERABLE_SIGNATURES:
        if signature in banner_lower:
            return "[VULNERABLE]"
    return ""


def scan_one_port(ip: str, port: int):
    """Scan a single port, identify its service and check it.

    If the global DELAY is set, sleep for DELAY seconds before the
    scan attempt to slow the scan down (stealth mode).

    Args:
        ip: Target IP address or hostname.
        port: TCP port to scan.

    Returns:
        A dict with the keys port, state, service and vulnerability
        if the port is open, None otherwise.
    """
    if DELAY > 0:
        print(f"[DEBUG] Sleeping {DELAY}s before next packet...")
        time.sleep(DELAY)
    if check_port(ip, port):
        service = get_service_info(ip, port)
        vulnerable = check_vulnerability(service) != ""
        return {
            'port': port,
            'state': 'open',
            'service': service,
            'vulnerability': 'YES' if vulnerable else 'NO',
        }
    return None


def scan_ports(ip: str, start_port: int, end_port: int) -> list:
    """Scan a range of TCP ports with a thread pool and identify services.

    Args:
        ip: Target IP address or hostname.
        start_port: First port to scan (included).
        end_port: Last port to scan (included).

    Returns:
        A list of dicts like {'port': 21, 'state': 'open',
        'service': 'vsftpd 2.3.4', 'vulnerability': 'YES'},
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
                line = f"[+] Port {result['port']} Open: {result['service']}"
                if result['vulnerability'] == 'YES':
                    line += " [VULNERABLE]"
                print(line)
                open_ports.append(result)
    return sorted(open_ports, key=lambda entry: entry['port'])


def save_json(results: list, filename: str) -> None:
    """Save scan results to a JSON file.

    Args:
        results: The list of dicts returned by scan_ports.
        filename: Path of the JSON file to write.
    """
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(results, file, indent=2)


def parse_port_range(value: str) -> tuple:
    """Parse a port range like "1-1000" or a single port like "80".

    Args:
        value: The port range given on the command line.

    Returns:
        A (start_port, end_port) tuple.

    Raises:
        argparse.ArgumentTypeError: If the range is invalid.
    """
    try:
        if "-" in value:
            start, end = (int(part) for part in value.split("-", 1))
        else:
            start = end = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"invalid port range '{value}' (expected e.g. 1-1000)")
    if not 1 <= start <= end <= 65535:
        raise argparse.ArgumentTypeError(
            f"invalid port range '{value}' (ports must be 1-65535)")
    return start, end


def parse_delay(value: str) -> float:
    """Parse the delay argument as a non-negative float.

    Args:
        value: The delay given on the command line.

    Returns:
        The delay in seconds.

    Raises:
        argparse.ArgumentTypeError: If the delay is invalid.
    """
    try:
        delay = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"invalid delay '{value}' (expected a number, e.g. 0.5)")
    if delay < 0:
        raise argparse.ArgumentTypeError(
            f"invalid delay '{value}' (must be positive)")
    return delay


def parse_args():
    """Parse the command line arguments.

    Returns:
        The parsed arguments namespace.
    """
    parser = argparse.ArgumentParser(
        description="NetProbe: a simple network probing tool.")
    parser.add_argument("-t", "--target",
                        help="target IP address or hostname")
    parser.add_argument("-p", "--ports", type=parse_port_range,
                        default=(1, 1024),
                        help="port range to scan, e.g. 1-1000 "
                             "(default: 1-1024)")
    parser.add_argument("-o", "--output",
                        help="save the results to this JSON file")
    parser.add_argument("-d", "--delay", type=parse_delay, default=0,
                        help="seconds to wait before each scan attempt "
                             "(default: 0)")
    return parser.parse_args()


def main():
    """Entry point of NetProbe."""
    global DELAY
    args = parse_args()
    DELAY = args.delay
    print(f"NetProbe v{VERSION} initialized...")
    if not args.target:
        return
    start_port, end_port = args.ports
    start = time.perf_counter()
    results = scan_ports(args.target, start_port, end_port)
    elapsed = time.perf_counter() - start
    print(f"Scan completed in {elapsed:.2f} seconds")
    if args.output:
        save_json(results, args.output)
        print(f"[*] Results saved to {args.output}")


if __name__ == "__main__":
    main()
