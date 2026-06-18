#!/bin/bash
tcpdump -i eth1 -w capture.cap '(icmp and host 10.42.0.1) or (tcp port 80 and host 10.82.82.130)'