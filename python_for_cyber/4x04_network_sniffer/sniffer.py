#!/usr/bin/env python3

import argparse
from scapy.all import sniff, Packet, IP, TCP, UDP, ICMP


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
        print(dir(self.__init__))
        args = self.get_cli_parser()
        sniff_args = {"store": False}

        if args.search:
            self.search_string = args.search

        try:
            sniff(prn=self._process_packet, **sniff_args)
        except KeyboardInterrupt:
            print(self.stats)
            print("\n[INFO] Stopping capture...")

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
        if packet.haslayer(IP):
            if packet.haslayer(TCP):
                self.stats['TCP'] += 1
                self.processors["TCP"].process(packet, self.search_string)
            elif packet.haslayer(UDP):
                self.stats['UDP'] += 1
            elif packet.haslayer(ICMP):
                self.stats['ICMP'] += 1
            else:
                print("UNKNOWN:", packet)


class PacketProcessor:
    def process(self, packet):
        raise NotImplementedError


class TCPProcessor(PacketProcessor):
    def process(self, packet, search_string):
        print("[TCP]")


def main() -> None:
    """Entry Point
    """
    print("[INFO] PySniffer initialized.")
    sniffer = Sniffer("eth0",
                      "tcp or udp or icmp",
                      "capture.pcap",
                      "password")
    sniffer.start()


if __name__ == '__main__':
    main()
