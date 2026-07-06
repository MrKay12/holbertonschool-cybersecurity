#!/bin/bash
tshark -r "$1" -T fields -e ip.src | sort | uniq -c | sort -nr | awk '{print $2}'