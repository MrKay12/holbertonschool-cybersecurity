#!/usr/bin/env python3
"""PySniffer: a lightweight packet sniffer built on Scapy.

Captures live packets from the network and prints a one-line
summary of each one on stdout. Errors are reported on stderr
with a user-friendly message, never with a raw traceback.
"""

import os
import sys

try:
    from scapy.all import sniff
except ImportError:
    sniff = None

PACKET_COUNT = 5


def packet_handler(packet) -> None:
    """Print a one-line summary of a captured packet.

    Args:
        packet: the Scapy packet handed over by sniff().

    Returns:
        None. The summary is written to stdout.
    """
    print(packet.summary(), flush=True)


def has_root_privileges() -> bool:
    """Tell whether the script runs with root privileges.

    Returns:
        True if the effective user id is 0 (root), False otherwise.
    """
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def main() -> int:
    """Entry point: check the environment, then sniff packets.

    Returns:
        0 on success, 1 when Scapy is missing, privileges are
        insufficient or the capture fails.
    """
    print("[INFO] PySniffer initialized.", flush=True)

    if sniff is None:
        print("[ERROR] Scapy is not installed. "
              "Run: pip install -r requirements.txt", file=sys.stderr)
        return 1

    if not has_root_privileges():
        print("[ERROR] Root privileges required. Run with sudo.",
              file=sys.stderr)
        return 1

    try:
        sniff(count=PACKET_COUNT, prn=packet_handler)
    except PermissionError:
        print("[ERROR] Permission denied. Run with sudo.",
              file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[INFO] Capture stopped by user.")
    except OSError as error:
        print(f"[ERROR] Capture failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
