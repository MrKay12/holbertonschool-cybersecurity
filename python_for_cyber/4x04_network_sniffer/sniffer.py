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


def packet_handler(packet) -> bool:
    """Print Scapy's one-line summary of a captured packet.

    Used as the fallback for packets that no protocol processor
    handles (e.g. ARP, IPv6).

    Args:
        packet: the Scapy packet handed over by sniff().

    Returns:
        True if the line was printed, False if the packet could
        not be read (a warning is printed on stderr).
    """
    try:
        print(packet.summary(), flush=True)
    except (AttributeError, TypeError):
        print("[WARN] Unreadable packet skipped.", file=sys.stderr)
        return False
    return True


class PacketProcessor:
    """Base class for protocol processors (Strategy pattern).

    Each subclass handles one protocol carried over IP: it names
    the Scapy layer it handles and implements process().

    Attributes:
        layer: the Scapy layer class this processor handles.
    """

    layer = None

    def matches(self, packet) -> bool:
        """Tell whether this processor handles the given packet.

        Args:
            packet: a Scapy packet that has an IP layer.

        Returns:
            True if the packet carries this processor's layer.
        """
        return self.layer is not None and packet.haslayer(self.layer)

    def process(self, packet) -> str:
        """Describe a packet and print the result.

        Args:
            packet: a Scapy packet carrying this processor's layer.

        Returns:
            The line printed on stdout.

        Raises:
            NotImplementedError: subclasses must override it.
        """
        raise NotImplementedError("process() must be implemented")


class TCPProcessor(PacketProcessor):
    """Describe TCP packets with ports and flags."""

    layer = TCP

    def process(self, packet) -> str:
        """Print "[TCP] SRC:PORT -> DST:PORT | Flags: X".

        Args:
            packet: a Scapy packet with IP and TCP layers.

        Returns:
            The line printed on stdout.
        """
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        sport = tcp_layer.sport
        dport = tcp_layer.dport
        flags = tcp_layer.flags
        line = (f"[TCP] {ip_layer.src}:{sport} -> {ip_layer.dst}:{dport}"
                f" | Flags: {flags}")
        print(line, flush=True)
        return line


class UDPProcessor(PacketProcessor):
    """Describe UDP packets."""

    layer = UDP

    def process(self, packet) -> str:
        """Print "[UDP] SRC -> DST".

        Args:
            packet: a Scapy packet with IP and UDP layers.

        Returns:
            The line printed on stdout.
        """
        line = f"[UDP] {packet[IP].src} -> {packet[IP].dst}"
        print(line, flush=True)
        return line


class ICMPProcessor(PacketProcessor):
    """Describe ICMP packets."""

    layer = ICMP

    def process(self, packet) -> str:
        """Print "[ICMP] SRC -> DST".

        Args:
            packet: a Scapy packet with IP and ICMP layers.

        Returns:
            The line printed on stdout.
        """
        line = f"[ICMP] {packet[IP].src} -> {packet[IP].dst}"
        print(line, flush=True)
        return line


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
        processors: PacketProcessor instances, tried in order.
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
        self.processors = [TCPProcessor(), UDPProcessor(), ICMPProcessor()]

    def start(self) -> int:
        """Check the environment, then sniff until Ctrl+C.

        Privileges are checked up front (a warning is printed when
        not root) and enforced by catching the PermissionError that
        sniff() raises when the capture is refused.

        Returns:
            0 when the capture ends cleanly, 1 when Scapy is
            missing, privileges are insufficient or the capture
            fails. A pcap file that cannot be opened only disables
            saving (a warning is printed).
        """
        if sniff is None:
            print("[ERROR] Scapy is not installed. "
                  "Run: pip install -r requirements.txt", file=sys.stderr)
            return 1

        if not has_root_privileges():
            print("[WARN] Not running as root: the capture will likely "
                  "be refused. Run with sudo.", file=sys.stderr)

        if self.output_file and not self._open_pcap_writer():
            print("[WARN] Capturing without saving packets.",
                  file=sys.stderr)

        packet_handler = self._process_packet
        try:
            sniff(prn=packet_handler, iface=self.interface,
                  filter=self.filter_str, store=False)
        except KeyboardInterrupt:
            pass
        except PermissionError:
            print("[ERROR] Root privileges required. Run with sudo.",
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

        The description is delegated to the matching protocol
        processor (see get_processor()).

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
        if not self._dispatch(packet):
            return
        if self.verbose and hexdump is not None:
            try:
                hexdump(packet)
            except (TypeError, ValueError) as error:
                print(f"[WARN] Hex dump failed: {error}", file=sys.stderr)

    def get_processor(self, packet):
        """Find the processor that handles a packet.

        Args:
            packet: the Scapy packet handed over by sniff().

        Returns:
            The matching PacketProcessor, or None if the packet is
            not IP or carries no supported protocol.
        """
        if IP is None or not packet.haslayer(IP):
            return None
        for processor in self.processors:
            if processor.matches(packet):
                return processor
        return None

    def _dispatch(self, packet) -> bool:
        """Delegate a packet to its processor, or fall back.

        Args:
            packet: the Scapy packet handed over by sniff().

        Returns:
            True if a line was printed, False if the packet could
            not be read (a warning is printed on stderr).
        """
        try:
            processor = self.get_processor(packet)
            if processor is None:
                return packet_handler(packet)
            processor.process(packet)
        except (AttributeError, IndexError, TypeError):
            print("[WARN] Unreadable packet skipped.", file=sys.stderr)
            return False
        return True

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
