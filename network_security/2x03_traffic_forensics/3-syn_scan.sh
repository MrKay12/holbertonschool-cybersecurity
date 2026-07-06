#!/bin/bash
tshark -r "$1" -Y "tcp.flags.syn==1 && tcp.flags.ack==0" | wc -l