# PySniffer

![Python](https://img.shields.io/badge/python-3.8%2B-blue?logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/scapy-2.5%2B-orange)
![Pylint](https://img.shields.io/badge/pylint-10.00%2F10-brightgreen)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey?logo=linux&logoColor=white)

> "Traffic never lies. People do."

## Description

**PySniffer** is a lightweight, command-line packet sniffer built on
[Scapy](https://scapy.net/). It works like a minimal Tshark: it captures
live traffic, dissects each packet and prints a one-line summary, without
any GUI or heavy dependency.

Features:

- **Live capture** on any interface, until `Ctrl+C`.
- **BPF filtering** (e.g. `"tcp port 80"`, `"icmp"`).
- **Protocol dissection** for TCP (ports + flags), UDP and ICMP;
  other packets fall back to Scapy's `summary()`.
- **Payload search (DPI)**: raises an alert when a string (e.g. a
  cleartext password) appears in a packet payload.
- **Hex dump** of every packet in verbose mode (like `tcpdump -X`).
- **PCAP export** to analyze the capture later in Wireshark.
- **Statistics** per protocol when the capture stops.
- **No raw tracebacks**: every expected error prints a clear `[ERROR]`.

Example output:

```text
[INFO] PySniffer initialized.
[TCP] 192.168.1.5:49812 -> 1.1.1.1:80 | Flags: S
[UDP] 192.168.1.5 -> 8.8.8.8
[ICMP] 192.168.1.5 -> 1.1.1.1
[TCP] 192.168.1.5:5000 -> 10.0.0.1:21 | Flags: PA
[ALERT] Payload Match found!
^C
[INFO] Stopping capture...
[INFO] Capture statistics:
  PROTOCOL  PACKETS
  TCP             2
  UDP             1
  ICMP            1
  OTHER           0
  TOTAL           4
```

## Installation

Requirements: Linux (Kali, ParrotOS, Ubuntu), Python 3.8+ and root
privileges for capturing.

```bash
git clone https://github.com/MrKay12/holbertonschool-cybersecurity.git
cd holbertonschool-cybersecurity/python_for_cyber/4x04_network_sniffer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

Sniffing needs root, so run the script with the venv's interpreter
under `sudo`:

```bash
sudo venv/bin/python3 sniffer.py [options]
```

| Option | Description |
|---|---|
| `-i`, `--interface IFACE` | Interface to sniff on (default: all) |
| `-f`, `--filter BPF` | BPF filter string, e.g. `"tcp port 80"` |
| `-s`, `--search STRING` | Alert when a payload contains `STRING` |
| `-v`, `--verbose` | Print a hex dump after each packet |
| `-w`, `--write FILE` | Append captured packets to a `.pcap` file |
| `-h`, `--help` | Show help and exit |

Examples:

```bash
# Everything on eth0
sudo venv/bin/python3 sniffer.py -i eth0

# Only pings
sudo venv/bin/python3 sniffer.py --filter "icmp"

# Hunt cleartext FTP passwords and keep a copy for Wireshark
sudo venv/bin/python3 sniffer.py -f "tcp port 21" -s "PASS" -w ftp.pcap

# Full hex dump of HTTP traffic
sudo venv/bin/python3 sniffer.py -f "tcp port 80" -v
```

Press `Ctrl+C` to stop: the remaining packets are processed, then the
statistics are printed and the pcap file is closed.

### Tests

Unit tests build fake packets in memory (no network, no root needed):

```bash
python3 tests.py -v
```

## Architecture

```text
             Thread 1 (capture)                 Thread 2 (processing)
 network --> sniff(prn=packet_handler) --put--> Queue --get--> Sniffer._process_packet()
                                                                 |-- PcapWriter (save)
                                                                 |-- get_processor()
                                                                 |     |-- TCPProcessor
                                                                 |     |-- UDPProcessor
                                                                 |     `-- ICMPProcessor
                                                                 |-- stats
                                                                 `-- hexdump (verbose)
```

**Why a Thread and a Queue?** Printing to the console is slow, blocking
I/O. If parsing and printing ran inside the `sniff()` callback, a burst
of traffic would make the capture fall behind and the kernel would drop
packets. PySniffer decouples the two:

1. **Capture thread**: `sniff()` calls `packet_handler()`, which only
   puts the packet into a `queue.Queue` and returns immediately.
2. **Processing thread**: a worker gets packets from the queue, parses
   them and prints the results at its own pace. The queue absorbs
   traffic bursts.
3. **Clean shutdown**: on `Ctrl+C`, a `None` sentinel is queued; the
   worker finishes every packet still waiting, then exits. Only then
   are the statistics printed, so the output is the same as a
   single-threaded run.

**Strategy pattern for protocols.** Each protocol has its own class
inheriting from `PacketProcessor` and implementing `process(packet)`.
`Sniffer` simply delegates each packet to the processor whose layer it
carries. Supporting a new protocol means adding one class, without
touching the capture code.

**Fast PCAP writing.** A single `PcapWriter(append=True, sync=False)` is
opened once and buffers writes, instead of reopening the file for every
packet.

| File | Role |
|---|---|
| `sniffer.py` | The tool (CLI, `Sniffer`, processors) |
| `tests.py` | Unit tests with mocked packets |
| `requirements.txt` | Python dependencies |

## Author

Holberton School cybersecurity project - *Python for Cyber*.
