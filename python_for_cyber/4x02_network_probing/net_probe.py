#!/usr/bin/env python3
"""NetProbe: a simple network probing tool."""

import socket

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


def main():
    """Entry point of NetProbe."""
    print(f"NetProbe v{VERSION} initialized...")
    print(f"Port 80 is open: {check_port('google.com', 80)}")
    print(f"Port 81 is open: {check_port('google.com', 81)}")


if __name__ == "__main__":
    main()