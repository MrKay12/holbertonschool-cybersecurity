#!/usr/bin/env python3
"""PySniffer: a lightweight packet sniffer built on Scapy.

Captures live packets from the network and prints a one-line
summary of each one on stdout. Errors are reported on stderr
with a user-friendly message, never with a raw traceback.
"""

import argparse
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

try:
    from scapy.error import Scapy_Exception
except ImportError:
    Scapy_Exception = OSError

try:
    from scapy.utils import PcapWriter
except ImportError:
    PcapWriter = None

try:
    from scapy.utils import hexdump
except ImportError:
    hexdump = None

# Set from -v/--verbose in main(): print a hex dump after each line.
VERBOSE = False

# Opened once in main() when --write is given, then shared with the
# sniff() callback. Writes are buffered (sync=False) and flushed on
# close, which is much faster than reopening the file per packet.
PCAP_WRITER = None


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


def describe_packet(packet) -> str:
    """Build the one-line description of a packet.

    Args:
        packet: the Scapy packet handed over by sniff().

    Returns:
        "[TCP] SRC:PORT -> DST:PORT | Flags: X" for TCP,
        "[PROTOCOL] SRC -> DST" for UDP and ICMP, or Scapy's
        packet.summary() for any other packet.
    """
    if IP is not None and packet.haslayer(IP):
        protocol = get_protocol_name(packet)
        if protocol == "TCP":
            return format_tcp(packet)
        if protocol:
            return f"[{protocol}] {packet[IP].src} -> {packet[IP].dst}"
    return packet.summary()


def packet_handler(packet) -> None:
    """Handle one captured packet: save, describe and dump it.

    Args:
        packet: the Scapy packet handed over by sniff().

    Returns:
        None. The description is written to stdout, followed by
        hexdump(packet) when --verbose is on. When --write is used,
        the packet is also appended to the pcap file.
    """
    if PCAP_WRITER is not None:
        try:
            PCAP_WRITER.write(packet)
        except (OSError, ValueError, TypeError, AttributeError) as error:
            print(f"[WARN] Packet not saved: {error}", file=sys.stderr)
    try:
        print(describe_packet(packet), flush=True)
    except (AttributeError, IndexError, TypeError):
        print("[WARN] Unreadable packet skipped.", file=sys.stderr)
        return
    if VERBOSE and hexdump is not None:
        try:
            hexdump(packet)
        except (TypeError, ValueError) as error:
            print(f"[WARN] Hex dump failed: {error}", file=sys.stderr)


def has_root_privileges() -> bool:
    """Tell whether the script runs with root privileges.

    Returns:
        True if the effective user id is 0 (root), False otherwise.
    """
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def parse_arguments() -> argparse.Namespace:
    """Parse the command line options.

    Returns:
        A namespace with "interface" (str or None), "filter"
        (BPF string or None), "verbose" (bool) and "write"
        (pcap path or None).
    """
    parser = argparse.ArgumentParser(
        prog="PySniffer",
        description="Capture and dissect live network packets."
    )
    parser.add_argument("-i", "--interface",
                        help="network interface to sniff on (e.g. eth0)")
    parser.add_argument("-f", "--filter",
                        help='BPF filter string (e.g. "tcp port 80")')
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="print a hex dump of each packet")
    parser.add_argument("-w", "--write", metavar="OUTPUT.pcap",
                        help="append captured packets to a pcap file")
    return parser.parse_args()


def open_pcap_writer(path: str):
    """Open a buffered pcap writer that appends to a file.

    Args:
        path: destination .pcap file, created if it does not exist.

    Returns:
        A scapy PcapWriter, or None if the file cannot be opened
        (an [ERROR] message is printed on stderr).
    """
    if PcapWriter is None:
        print("[ERROR] PcapWriter is unavailable in this Scapy install.",
              file=sys.stderr)
        return None
    try:
        return PcapWriter(path, append=True, sync=False)
    except PermissionError:
        print(f"[ERROR] Permission denied: cannot write {path}.",
              file=sys.stderr)
    except FileNotFoundError:
        print(f"[ERROR] Directory not found for {path}.", file=sys.stderr)
    except OSError as error:
        print(f"[ERROR] Cannot open {path}: {error}", file=sys.stderr)
    return None


def close_pcap_writer() -> None:
    """Flush and close the global pcap writer, if one is open.

    Returns:
        None. Prints where the packets were saved.
    """
    global PCAP_WRITER
    if PCAP_WRITER is None:
        return
    try:
        PCAP_WRITER.close()
        print(f"[INFO] Packets saved to {PCAP_WRITER.filename}.")
    except (OSError, AttributeError) as error:
        print(f"[ERROR] Could not finalize pcap file: {error}",
              file=sys.stderr)
    PCAP_WRITER = None


def main() -> int:
    """Entry point: check the environment, then sniff forever.

    The -i/--interface and -f/--filter options are passed to
    sniff() as iface and filter (BPF syntax). With -w/--write,
    every packet is also appended to the given pcap file. With
    -v/--verbose, a hex dump follows each summary line.

    The capture runs until the user presses Ctrl+C, then the
    script prints "[INFO] Stopping capture..." and exits cleanly.

    Returns:
        0 on success, 1 when Scapy is missing, privileges are
        insufficient or the capture fails.
    """
    global PCAP_WRITER, VERBOSE
    print("[INFO] PySniffer initialized.", flush=True)
    args = parse_arguments()
    VERBOSE = args.verbose

    if sniff is None:
        print("[ERROR] Scapy is not installed. "
              "Run: pip install -r requirements.txt", file=sys.stderr)
        return 1

    if not has_root_privileges():
        print("[ERROR] Root privileges required. Run with sudo.",
              file=sys.stderr)
        return 1

    if args.write:
        PCAP_WRITER = open_pcap_writer(args.write)
        if PCAP_WRITER is None:
            return 1

    try:
        sniff(prn=packet_handler, iface=args.interface,
              filter=args.filter, store=False)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("[ERROR] Permission denied. Run with sudo.",
              file=sys.stderr)
        close_pcap_writer()
        return 1
    except (OSError, ValueError, Scapy_Exception) as error:
        print(f"[ERROR] Capture failed: {error}", file=sys.stderr)
        close_pcap_writer()
        return 1
    print("\n[INFO] Stopping capture...", flush=True)
    close_pcap_writer()
    return 0


if __name__ == '__main__':
    EXIT_STATUS = main()
    if EXIT_STATUS != 0:
        sys.exit(EXIT_STATUS)
