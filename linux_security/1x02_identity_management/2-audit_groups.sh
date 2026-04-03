#!/bin/bash
awk -F: '$3>=1000{print $1}' "$1" | while read u; do id -nG "$u" 2>/dev/null | tr ' ' '\n' | grep -E '^(disk|docker|shadow)$' | sed "s/^/$u:/"; done
