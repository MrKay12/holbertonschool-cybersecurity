#!/usr/bin/env python3

import argparse
import sys


class Sniffer:
    def __init__(self, interface, filter_str, output_file, search_string):
        self.interface = interface
        self.filter_str = filter_str
        self.output_file = output_file
        self.search_string = search_string
        self.stats = {
            'TCP': 0,
            'UDP': 0,
            'ICMP': 0,
        }
        self.processors = {
            "TCP": TCPProcessor(),
        }

    def start(self):
        """sniffer start
        """
        args = self.get_cli_parser()

        if args.search:
            self.search_string = args.search

        try:
            from scapy.all import sniff, IP, TCP, UDP, ICMP
        except ImportError:
            print("[ERROR] scapy is not installed "
                  "(pip install -r requirements.txt)", file=sys.stderr)
            return 1
        self.layers = {"IP": IP, "TCP": TCP, "UDP": UDP, "ICMP": ICMP}

        sniff_args = {"store": False}
        if args.interface:
            sniff_args["iface"] = args.interface
        if args.filter:
            sniff_args["filter"] = args.filter

        try:
            sniff(prn=self._process_packet, **sniff_args)
        except PermissionError:
            print("[ERROR] Permission denied: run as root",
                  file=sys.stderr)
            return 1
        except KeyboardInterrupt:
            pass
        print("\n[INFO] Stopping capture...")
        print(self.stats)
        return 0

    def get_cli_parser(self):
        parser = argparse.ArgumentParser(
            prog="PySniffer",
            description="Capture packets"
        )

        parser.add_argument("-i", "--interface", help="Interface to sniff")
        parser.add_argument("-f", "--filter", help="BPF filter to use")
        parser.add_argument("-v",
                            "--verbose",
                            help="Verbose mode",
                            action="store_true")
        parser.add_argument("--write", help="Write result on file")
        parser.add_argument("-s", "--search", help="Search for pattern")
        return parser.parse_args()

    def _process_packet(self, packet):
        """Get packet details
        """
        layers = self.layers
        if packet.haslayer(layers["IP"]):
            if packet.haslayer(layers["TCP"]):
                self.stats['TCP'] += 1
                self.processors["TCP"].process(packet, self.search_string)
            elif packet.haslayer(layers["UDP"]):
                self.stats['UDP'] += 1
            elif packet.haslayer(layers["ICMP"]):
                self.stats['ICMP'] += 1
            else:
                print("UNKNOWN:", packet)


class PacketProcessor:
    def process(self, packet):
        raise NotImplementedError


class TCPProcessor(PacketProcessor):
    def process(self, packet, search_string):
        print("[TCP]")


def main() -> int:
    """Entry Point
    """
    print("[INFO] PySniffer initialized.", flush=True)
    sniffer = Sniffer("eth0",
                      "tcp or udp or icmp",
                      "capture.pcap",
                      "password")
    return sniffer.start()


if __name__ == '__main__':
    sys.exit(main())
