#!/usr/bin/env python3
"""PySniffer: a lightweight packet sniffer built on Scapy.

Captures live packets from the network and prints a one-line
description of each one on stdout. Packets can be filtered (BPF),
dumped in hex and saved to a pcap file. Errors are reported on
stderr with a user-friendly message, never with a raw traceback.
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
    from scapy.utils import PcapWriter, hexdump
except ImportError:
    PcapWriter = hexdump = None


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


def packet_handler(packet) -> bool:
    """Print the one-line description of a captured packet.

    Args:
        packet: the Scapy packet handed over by sniff().

    Returns:
        True if the line was printed, False if the packet could
        not be read (a warning is printed on stderr).
    """
    try:
        print(describe_packet(packet), flush=True)
    except (AttributeError, IndexError, TypeError):
        print("[WARN] Unreadable packet skipped.", file=sys.stderr)
        return False
    return True


def has_root_privileges() -> bool:
    """Tell whether the script runs with root privileges.

    Returns:
        True if the effective user id is 0 (root), False otherwise.
    """
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


class Sniffer:
    """Live packet sniffer: capture, describe, dump and save packets.

    Attributes:
        interface: interface to sniff on, or None for all.
        filter_str: BPF filter string, or None for no filter.
        output_file: pcap path to append packets to, or None.
        verbose: when True, print a hex dump after each line.
    """

    def __init__(self, interface, filter_str, output_file,
                 verbose: bool = False):
        """Store the capture settings.

        Args:
            interface: interface name (e.g. "eth0") or None.
            filter_str: BPF filter (e.g. "tcp port 80") or None.
            output_file: pcap file path or None to skip saving.
            verbose: print hexdump(packet) after each line if True.
        """
        self.interface = interface
        self.filter_str = filter_str
        self.output_file = output_file
        self.verbose = verbose
        self.pcap_writer = None

    def start(self) -> int:
        """Check the environment, then sniff until Ctrl+C.

        Returns:
            0 when the capture ends cleanly, 1 when Scapy is
            missing, privileges are insufficient, the pcap file
            cannot be opened or the capture fails.
        """
        if sniff is None:
            print("[ERROR] Scapy is not installed. "
                  "Run: pip install -r requirements.txt", file=sys.stderr)
            return 1

        if not has_root_privileges():
            print("[ERROR] Root privileges required. Run with sudo.",
                  file=sys.stderr)
            return 1

        if self.output_file and not self._open_pcap_writer():
            return 1

        packet_handler = self._process_packet
        try:
            sniff(prn=packet_handler, iface=self.interface,
                  filter=self.filter_str, store=False)
        except KeyboardInterrupt:
            pass
        except PermissionError:
            print("[ERROR] Permission denied. Run with sudo.",
                  file=sys.stderr)
            self._close_pcap_writer()
            return 1
        except (OSError, ValueError, Scapy_Exception) as error:
            print(f"[ERROR] Capture failed: {error}", file=sys.stderr)
            self._close_pcap_writer()
            return 1
        print("\n[INFO] Stopping capture...", flush=True)
        self._close_pcap_writer()
        return 0

    def _process_packet(self, packet) -> None:
        """sniff() callback: save, describe and dump one packet.

        Args:
            packet: the Scapy packet handed over by sniff().

        Returns:
            None. Output goes to stdout and to the pcap file.
        """
        if self.pcap_writer is not None:
            try:
                self.pcap_writer.write(packet)
            except (OSError, ValueError, TypeError,
                    AttributeError) as error:
                print(f"[WARN] Packet not saved: {error}",
                      file=sys.stderr)
        if not packet_handler(packet):
            return
        if self.verbose and hexdump is not None:
            try:
                hexdump(packet)
            except (TypeError, ValueError) as error:
                print(f"[WARN] Hex dump failed: {error}", file=sys.stderr)

    def _open_pcap_writer(self) -> bool:
        """Open a buffered pcap writer appending to output_file.

        Writes are buffered (sync=False) and flushed on close, which
        is much faster than reopening the file for every packet.

        Returns:
            True if the writer is ready, False otherwise (an
            [ERROR] message is printed on stderr).
        """
        if PcapWriter is None:
            print("[ERROR] PcapWriter is unavailable in this Scapy install.",
                  file=sys.stderr)
            return False
        try:
            self.pcap_writer = PcapWriter(self.output_file, append=True,
                                          sync=False)
            return True
        except PermissionError:
            print(f"[ERROR] Permission denied: cannot write "
                  f"{self.output_file}.", file=sys.stderr)
        except FileNotFoundError:
            print(f"[ERROR] Directory not found for {self.output_file}.",
                  file=sys.stderr)
        except OSError as error:
            print(f"[ERROR] Cannot open {self.output_file}: {error}",
                  file=sys.stderr)
        return False

    def _close_pcap_writer(self) -> None:
        """Flush and close the pcap writer, if one is open.

        Returns:
            None. Prints where the packets were saved.
        """
        if self.pcap_writer is None:
            return
        try:
            self.pcap_writer.close()
            print(f"[INFO] Packets saved to {self.output_file}.")
        except (OSError, AttributeError) as error:
            print(f"[ERROR] Could not finalize pcap file: {error}",
                  file=sys.stderr)
        self.pcap_writer = None


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


def main() -> int:
    """Entry point: parse the options and run the sniffer.

    Returns:
        The exit status returned by Sniffer.start().
    """
    print("[INFO] PySniffer initialized.", flush=True)
    args = parse_arguments()
    sniffer = Sniffer(args.interface, args.filter, args.write,
                      verbose=args.verbose)
    return sniffer.start()


if __name__ == '__main__':
    EXIT_STATUS = main()
    if EXIT_STATUS != 0:
        sys.exit(EXIT_STATUS)
