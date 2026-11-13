# PySniffer - Network Sniffer

A lightweight packet sniffer written in Python with Scapy.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

Sniffing requires root privileges:

```bash
sudo venv/bin/python3 ./sniffer.py
```

## Tasks

### 0. Initialization
`sniffer.py` prints `[INFO] PySniffer initialized.` on startup and
handles errors (missing Scapy, missing privileges) without tracebacks.

### 1. The Basic Sniffer
`packet_handler(packet)` prints `packet.summary()` for each packet.
`sniff(count=5, prn=packet_handler)` captures 5 packets.

Example output:

```
Ether / IP / TCP 192.168.1.5:54321 > 1.1.1.1:80 S
Ether / IP / UDP 192.168.1.5:123 > 8.8.8.8:123
```
