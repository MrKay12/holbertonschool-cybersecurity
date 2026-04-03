#!/bin/bash
awk -F: '$3>=1000{print $1}' "$1" | while read u; do grep -E '^(disk|docker|shadow):' /etc/group | grep -w "$u" | cut -d: -f1 | sed "s/^/$u:/"; done
