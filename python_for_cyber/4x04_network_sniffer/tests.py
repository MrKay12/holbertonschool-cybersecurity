#!/usr/bin/env python3
"""Unit tests for PySniffer (sniffer.py), without any network.

Packets are built in memory with Scapy (e.g.
IP(src="1.1.1.1")/TCP(dport=80)) and handed directly to the
processors and to the Sniffer class, so no capture and no root
privileges are needed.

Run with: python3 tests.py
"""

import contextlib
import io
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import sniffer  # noqa: E402

try:
    from scapy.all import IP, TCP, UDP, ICMP, ARP, Ether, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def run_silently(function, *args):
    """Call a function while capturing what it prints.

    Args:
        function: the callable to run.
        *args: positional arguments passed to it.

    Returns:
        A (return_value, printed_text) tuple.
    """
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        result = function(*args)
    return result, buffer.getvalue()


@unittest.skipUnless(SCAPY_AVAILABLE, "Scapy is not installed")
class TestTCPProcessor(unittest.TestCase):
    """TCPProcessor extracts IPs, ports and flags correctly."""

    def setUp(self):
        """Build a fake TCP packet and a processor."""
        self.pkt = (IP(src="1.1.1.1", dst="2.2.2.2")
                    / TCP(sport=4444, dport=80, flags="S"))
        self.processor = sniffer.TCPProcessor()

    def test_extracts_source_ip(self):
        """The source IP is read from the IP layer."""
        self.assertEqual(
            self.processor.get_field(self.pkt, IP, "src"), "1.1.1.1")

    def test_extracts_destination_port(self):
        """The destination port is read from the TCP layer."""
        self.assertEqual(
            self.processor.get_field(self.pkt, TCP, "dport"), 80)

    def test_process_line(self):
        """process() prints and returns the formatted TCP line."""
        line, printed = run_silently(self.processor.process, self.pkt)
        self.assertEqual(line,
                         "[TCP] 1.1.1.1:4444 -> 2.2.2.2:80 | Flags: S")
        self.assertIn(line, printed)

    def test_minimal_packet(self):
        """The packet from the instructions is parsed correctly."""
        pkt = IP(src="1.1.1.1") / TCP(dport=80)
        line, _ = run_silently(self.processor.process, pkt)
        self.assertTrue(line.startswith("[TCP] 1.1.1.1:"))
        self.assertIn(":80 | Flags:", line)


@unittest.skipUnless(SCAPY_AVAILABLE, "Scapy is not installed")
class TestOtherProcessors(unittest.TestCase):
    """UDP and ICMP processors print "[PROTO] SRC -> DST"."""

    def test_udp(self):
        """UDPProcessor formats source and destination IPs."""
        pkt = IP(src="10.0.0.1", dst="8.8.8.8") / UDP(dport=53)
        line, _ = run_silently(sniffer.UDPProcessor().process, pkt)
        self.assertEqual(line, "[UDP] 10.0.0.1 -> 8.8.8.8")

    def test_icmp(self):
        """ICMPProcessor formats source and destination IPs."""
        pkt = IP(src="10.0.0.1", dst="1.1.1.1") / ICMP()
        line, _ = run_silently(sniffer.ICMPProcessor().process, pkt)
        self.assertEqual(line, "[ICMP] 10.0.0.1 -> 1.1.1.1")

    def test_base_class_is_abstract(self):
        """PacketProcessor.process() must be overridden."""
        with self.assertRaises(NotImplementedError):
            sniffer.PacketProcessor().process(IP() / TCP())


@unittest.skipUnless(SCAPY_AVAILABLE, "Scapy is not installed")
class TestPayloadSearch(unittest.TestCase):
    """The Raw payload search raises an alert on a match only."""

    def test_match_prints_alert(self):
        """A payload containing the string triggers the alert."""
        pkt = IP() / TCP(dport=21) / Raw(b"USER bob\r\nPASS secret\r\n")
        found, printed = run_silently(
            sniffer.TCPProcessor("secret").search_payload, pkt)
        self.assertTrue(found)
        self.assertIn("[ALERT] Payload Match found!", printed)

    def test_no_match(self):
        """A payload without the string triggers nothing."""
        pkt = IP() / TCP(dport=80) / Raw(b"GET / HTTP/1.1\r\n")
        found, printed = run_silently(
            sniffer.TCPProcessor("secret").search_payload, pkt)
        self.assertFalse(found)
        self.assertEqual(printed, "")

    def test_binary_payload_does_not_crash(self):
        """Undecodable bytes are ignored instead of raising."""
        pkt = IP() / UDP() / Raw(b"\xff\xfe\x00secret\x80")
        found, _ = run_silently(
            sniffer.UDPProcessor("secret").search_payload, pkt)
        self.assertTrue(found)


@unittest.skipUnless(SCAPY_AVAILABLE, "Scapy is not installed")
class TestSniffer(unittest.TestCase):
    """Sniffer dispatches packets, counts them and calls sniff()."""

    def setUp(self):
        """Create a Sniffer with no interface, filter or file."""
        self.sniffer = sniffer.Sniffer(None, None, None)

    def test_dispatch(self):
        """Each packet goes to the processor of its protocol."""
        cases = [(IP() / TCP(), sniffer.TCPProcessor),
                 (IP() / UDP(), sniffer.UDPProcessor),
                 (IP() / ICMP(), sniffer.ICMPProcessor)]
        for pkt, expected in cases:
            self.assertIsInstance(self.sniffer.get_processor(pkt), expected)
        self.assertIsNone(self.sniffer.get_processor(Ether() / ARP()))

    def test_stats(self):
        """Processed packets are counted per protocol."""
        packets = [IP() / TCP(), IP() / TCP(), IP() / UDP(),
                   IP() / ICMP(), Ether() / ARP()]
        for pkt in packets:
            run_silently(self.sniffer._process_packet, pkt)
        self.assertEqual(self.sniffer.stats,
                         {'TCP': 2, 'UDP': 1, 'ICMP': 1, 'OTHER': 1})

    def test_start_calls_sniff_with_options(self):
        """start() passes interface and filter to sniff()."""
        engine = sniffer.Sniffer("lo", "tcp port 80", None)
        with mock.patch("sniffer.sniff") as fake_sniff, \
                mock.patch("sniffer.has_root_privileges",
                           return_value=True):
            status, _ = run_silently(engine.start)
        self.assertEqual(status, 0)
        kwargs = fake_sniff.call_args.kwargs
        self.assertEqual(kwargs["iface"], "lo")
        self.assertEqual(kwargs["filter"], "tcp port 80")


if __name__ == "__main__":
    unittest.main()
