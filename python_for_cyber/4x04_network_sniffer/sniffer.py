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

try:
    from scapy.all import IP, TCP, UDP, ICMP
except ImportError:
    IP = TCP = UDP = ICMP = None


def get_protocol_name(packet) -> str:
    """Identify the transport protocol carried by an IP packet.

    Args:
        packet: a Scapy packet that has an IP layer.

    Returns:
        "TCP", "UDP" or "ICMP", or an empty string if none matches.
    """
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    return ""


def format_tcp(packet) -> str:
    """Build the detailed line for a TCP packet.

    Args:
        packet: a Scapy packet that has both IP and TCP layers.

    Returns:
        A string like "[TCP] SRC:PORT -> DST:PORT | Flags: X".
    """
    ip_layer = packet[IP]
    tcp_layer = packet[TCP]
    sport = tcp_layer.sport
    dport = tcp_layer.dport
    flags = tcp_layer.flags
    return (f"[TCP] {ip_layer.src}:{sport} -> {ip_layer.dst}:{dport}"
            f" | Flags: {flags}")


def packet_handler(packet) -> None:
    """Print a one-line description of a captured packet.

    IP packets carrying TCP, UDP or ICMP are printed as
    "[PROTOCOL] SRC -> DST". Any other packet falls back to
    Scapy's packet.summary() one-liner.

    Args:
        packet: the Scapy packet handed over by sniff().

    Returns:
        None. The description is written to stdout.
    """
    try:
        if IP is not None and packet.haslayer(IP):
            protocol = get_protocol_name(packet)
            if protocol == "TCP":
                print(format_tcp(packet), flush=True)
                return
            if protocol:
                print(f"[{protocol}] {packet[IP].src} -> {packet[IP].dst}",
                      flush=True)
                return
        print(packet.summary(), flush=True)
    except (AttributeError, IndexError, TypeError):
        print("[WARN] Unreadable packet skipped.", file=sys.stderr)


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
    """Entry point: check the environment, then sniff forever.

    The capture runs until the user presses Ctrl+C, then the
    script prints "[INFO] Stopping capture..." and exits cleanly.

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
        sniff(prn=packet_handler, store=False)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("[ERROR] Permission denied. Run with sudo.",
              file=sys.stderr)
        return 1
    except OSError as error:
        print(f"[ERROR] Capture failed: {error}", file=sys.stderr)
        return 1
    print("\n[INFO] Stopping capture...", flush=True)
    return 0


if __name__ == '__main__':
    EXIT_STATUS = main()
    if EXIT_STATUS != 0:
        sys.exit(EXIT_STATUS)
