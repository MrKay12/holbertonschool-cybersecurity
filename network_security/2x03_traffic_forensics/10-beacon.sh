#!/bin/bash
tshark -r "$1" -Y "ip.addr" -T fields -e frame.time_epoch -e ip.src -e ip.dst