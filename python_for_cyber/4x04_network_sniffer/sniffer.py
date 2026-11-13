#!/usr/bin/env python3
"""PySniffer: a lightweight packet sniffer built on Scapy.

Captures live packets from the network and prints a one-line
description of each one on stdout. Packets can be filtered (BPF),
dumped in hex and saved to a pcap file. Errors are reported on
stderr with a user-friendly message, never with a raw traceback.
"""

import argparse
import os
import queue
import sys
import threading

try:
    from scapy.all import sniff
except ImportError:
    sniff = None

try:
    import scapy.all as scapy_all
except ImportError:
    scapy_all = None

# Looked up one by one so a partial Scapy (or a test double)
# missing one layer does not disable the others.
IP = getattr(scapy_all, "IP", None)
TCP = getattr(scapy_all, "TCP", None)
UDP = getattr(scapy_all, "UDP", None)
ICMP = getattr(scapy_all, "ICMP", None)
Raw = getattr(scapy_all, "Raw", None)

try:
    from scapy.error import Scapy_Exception as ScapyException
except ImportError:
    ScapyException = OSError

try:
    from scapy.utils import PcapWriter, hexdump
except ImportError:
    PcapWriter = hexdump = None


def print_summary(packet) -> bool:
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
        name: protocol label, used in output and statistics.
        layer: the Scapy layer class this processor handles.
        search_string: text looked for in the Raw payload, or None.
    """

    name = ""
    layer = None

    def __init__(self, search_string=None):
        """Create a processor.

        Args:
            search_string: text to look for in packet payloads
                (deep packet inspection), or None to disable it.
        """
        self.search_string = search_string

    def matches(self, packet) -> bool:
        """Tell whether this processor handles the given packet.

        Args:
            packet: a Scapy packet that has an IP layer.

        Returns:
            True if the packet carries this processor's layer.
        """
        return self.layer is not None and packet.haslayer(self.layer)

    def process(self, packet, search_string=None) -> str:
        """Describe a packet, print it, then search its payload.

        Args:
            packet: a Scapy packet carrying this processor's layer.
            search_string: optional payload search override.

        Returns:
            The line printed on stdout.

        Raises:
            NotImplementedError: subclasses must override it.
        """
        raise NotImplementedError("process() must be implemented")

    @staticmethod
    def payload_to_text(payload) -> str:
        """Convert a Raw payload to text without ever raising.

        Args:
            payload: the Raw "load" field (bytes, or str in tests).

        Returns:
            The decoded text; undecodable bytes are dropped.
        """
        if isinstance(payload, (bytes, bytearray)):
            return payload.decode("utf-8", errors="ignore")
        try:
            return str(payload)
        except (TypeError, ValueError):
            return ""

    def search_payload(self, packet, search_string=None) -> bool:
        """Look for the search string in the packet's Raw payload.

        Prints "[ALERT] Payload Match found!" when it matches.

        Args:
            packet: the packet to inspect.
            search_string: overrides self.search_string if given.

        Returns:
            True if the payload contains the search string.
        """
        needle = search_string or self.search_string
        if not needle or Raw is None:
            return False
        try:
            if not packet.haslayer(Raw):
                return False
        except (AttributeError, TypeError):
            return False
        text = self.payload_to_text(self.get_field(packet, Raw, "load", b""))
        if needle in text:
            print("[ALERT] Payload Match found!", flush=True)
            return True
        return False

    @staticmethod
    def get_field(packet, layer, name: str, default="?"):
        """Read a header field without ever raising.

        The field is looked up on the layer returned by
        packet.getlayer(layer), then on packet[layer], then on the
        packet itself (Scapy forwards unknown attributes to upper
        layers), first as an attribute, then in a "fields" dict.

        Args:
            packet: the packet to read from.
            layer: the Scapy layer class holding the field.
            name: field name, e.g. "src", "sport" or "flags".
            default: value returned when the field is not found.

        Returns:
            The field value, or default.
        """
        candidates = []
        for accessor in ("getlayer", "__getitem__"):
            try:
                candidates.append(getattr(packet, accessor)(layer))
            except (AttributeError, IndexError, KeyError, TypeError,
                    ValueError):
                continue
        candidates.append(packet)
        for candidate in candidates:
            if candidate is None:
                continue
            try:
                value = getattr(candidate, name)
            except (AttributeError, IndexError, KeyError, TypeError):
                fields = getattr(candidate, "fields", None)
                value = fields.get(name) if isinstance(fields, dict) else None
            if value is not None:
                return value
        return default


class TCPProcessor(PacketProcessor):
    """Describe TCP packets with ports and flags."""

    name = "TCP"
    layer = TCP

    def process(self, packet, search_string=None) -> str:
        """Print "[TCP] SRC:PORT -> DST:PORT | Flags: X".

        Args:
            packet: a Scapy packet with IP and TCP layers.
            search_string: optional payload search override.

        Returns:
            The line printed on stdout.
        """
        src = self.get_field(packet, IP, "src")
        dst = self.get_field(packet, IP, "dst")
        sport = self.get_field(packet, TCP, "sport")
        dport = self.get_field(packet, TCP, "dport")
        flags = self.get_field(packet, TCP, "flags")
        line = (f"[TCP] {src}:{sport} -> {dst}:{dport}"
                f" | Flags: {flags}")
        print(line, flush=True)
        self.search_payload(packet, search_string)
        return line


class UDPProcessor(PacketProcessor):
    """Describe UDP packets."""

    name = "UDP"
    layer = UDP

    def process(self, packet, search_string=None) -> str:
        """Print "[UDP] SRC -> DST".

        Args:
            packet: a Scapy packet with IP and UDP layers.
            search_string: optional payload search override.

        Returns:
            The line printed on stdout.
        """
        src = self.get_field(packet, IP, "src")
        dst = self.get_field(packet, IP, "dst")
        line = f"[UDP] {src} -> {dst}"
        print(line, flush=True)
        self.search_payload(packet, search_string)
        return line


class ICMPProcessor(PacketProcessor):
    """Describe ICMP packets."""

    name = "ICMP"
    layer = ICMP

    def process(self, packet, search_string=None) -> str:
        """Print "[ICMP] SRC -> DST".

        Args:
            packet: a Scapy packet with IP and ICMP layers.
            search_string: optional payload search override.

        Returns:
            The line printed on stdout.
        """
        src = self.get_field(packet, IP, "src")
        dst = self.get_field(packet, IP, "dst")
        line = f"[ICMP] {src} -> {dst}"
        print(line, flush=True)
        self.search_payload(packet, search_string)
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


class Sniffer:  # pylint: disable=too-many-instance-attributes
    """Live packet sniffer: capture, describe, dump and save packets.

    Attributes:
        interface: interface to sniff on, or None for all.
        filter_str: BPF filter string, or None for no filter.
        output_file: pcap path to append packets to, or None.
        search_string: text searched in payloads, or None.
        verbose: when True, print a hex dump after each line.
        processors: PacketProcessor instances, tried in order.
        stats: packet count per protocol ("OTHER" for the rest).
        packet_queue: hands packets from the capture thread to
            the processing thread.
        worker: the processing thread, while a capture runs.
    """

    def __init__(self, interface, filter_str, output_file,
                 search_string=None, verbose: bool = False):
        """Store the capture settings.

        Args:
            interface: interface name (e.g. "eth0") or None.
            filter_str: BPF filter (e.g. "tcp port 80") or None.
            output_file: pcap file path or None to skip saving.
            search_string: payload text to alert on, or None.
            verbose: print hexdump(packet) after each line if True.
        """
        self.interface = interface
        self.filter_str = filter_str
        self.output_file = output_file
        self.search_string = search_string
        self.verbose = verbose
        self.pcap_writer = None
        self.processors = [TCPProcessor(search_string),
                           UDPProcessor(search_string),
                           ICMPProcessor(search_string)]
        self.stats = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'OTHER': 0}
        self.packet_queue = queue.Queue()
        self.worker = None

    def start(self) -> int:
        """Check the environment, then sniff until Ctrl+C.

        Capture and processing are decoupled: sniff() (thread 1)
        only puts packets into a Queue, and a worker thread
        (thread 2) gets them, parses them and prints them, so slow
        console output never makes the capture drop packets.

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

        self._start_worker()

        def packet_handler(packet) -> None:
            """sniff() callback (capture thread): queue the packet.

            Args:
                packet: the Scapy packet handed over by sniff().
            """
            self._enqueue_packet(packet)

        try:
            sniff(prn=packet_handler, iface=self.interface,
                  filter=self.filter_str, store=False)
        except KeyboardInterrupt:
            pass
        except PermissionError:
            print("[ERROR] Root privileges required. Run with sudo.",
                  file=sys.stderr)
            self._stop_worker()
            self._close_pcap_writer()
            return 1
        except (OSError, ValueError, ScapyException) as error:
            print(f"[ERROR] Capture failed: {error}", file=sys.stderr)
            self._stop_worker()
            self._close_pcap_writer()
            return 1
        self._stop_worker()
        print("\n[INFO] Stopping capture...", flush=True)
        self.print_stats()
        self._close_pcap_writer()
        return 0

    def _enqueue_packet(self, packet) -> None:
        """sniff() callback (capture thread): queue one packet.

        Kept as cheap as possible so the capture never blocks on
        parsing or console output.

        Args:
            packet: the Scapy packet handed over by sniff().

        Returns:
            None.
        """
        self.packet_queue.put(packet)

    def _start_worker(self) -> None:
        """Start the processing thread that drains the queue.

        Returns:
            None. The thread is stored in self.worker.
        """
        self.worker = threading.Thread(target=self._worker_loop,
                                       name="PacketProcessor",
                                       daemon=True)
        self.worker.start()

    def _worker_loop(self) -> None:
        """Processing thread: get packets and process them.

        Runs until it gets the None sentinel put by _stop_worker().

        Returns:
            None.
        """
        while True:
            packet = self.packet_queue.get()
            try:
                if packet is None:
                    return
                self._process_packet(packet)
            except (AttributeError, IndexError, KeyError, TypeError,
                    ValueError, OSError) as error:
                print(f"[WARN] Packet processing failed: {error}",
                      file=sys.stderr)
            finally:
                self.packet_queue.task_done()

    def _stop_worker(self) -> None:
        """Let the worker finish the queued packets, then stop it.

        Returns:
            None. Every packet captured so far has been processed
            when this returns (unless Ctrl+C is pressed again).
        """
        if self.worker is None:
            return
        self.packet_queue.put(None)
        try:
            self.worker.join()
        except KeyboardInterrupt:
            print("[WARN] Remaining queued packets discarded.",
                  file=sys.stderr)
        self.worker = None

    def _process_packet(self, packet) -> None:
        """Processing thread: save, describe and dump one packet.

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

    def update_stats(self, processor) -> None:
        """Count one packet for the protocol of its processor.

        Args:
            processor: the PacketProcessor that handles the packet,
                or None for unsupported packets (counted as OTHER).

        Returns:
            None. self.stats is updated in place.
        """
        protocol = processor.name if processor is not None else "OTHER"
        self.stats[protocol] = self.stats.get(protocol, 0) + 1

    def print_stats(self) -> None:
        """Print the per-protocol packet counts as a table.

        Returns:
            None. The table is written to stdout.
        """
        total = sum(self.stats.values())
        print("[INFO] Capture statistics:")
        print(f"  {'PROTOCOL':<9}{'PACKETS':>8}")
        for protocol, count in self.stats.items():
            print(f"  {protocol:<9}{count:>8}")
        print(f"  {'TOTAL':<9}{total:>8}", flush=True)

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
            self.update_stats(processor)
            if processor is None:
                return print_summary(packet)
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
        (BPF string or None), "search" (str or None), "verbose"
        (bool) and "write" (pcap path or None).
    """
    parser = argparse.ArgumentParser(
        prog="PySniffer",
        description="Capture and dissect live network packets."
    )
    parser.add_argument("-i", "--interface",
                        help="network interface to sniff on (e.g. eth0)")
    parser.add_argument("-f", "--filter",
                        help='BPF filter string (e.g. "tcp port 80")')
    parser.add_argument("-s", "--search", metavar="STRING",
                        help="alert when a payload contains STRING")
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
                      search_string=args.search, verbose=args.verbose)
    return sniffer.start()


if __name__ == '__main__':
    EXIT_STATUS = main()
    if EXIT_STATUS != 0:
        sys.exit(EXIT_STATUS)
