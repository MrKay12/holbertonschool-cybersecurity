#!/bin/bash

set -e

LOG_FILE="/var/log/squid/access.log"

awk '{print $8}' "$LOG_FILE" \
    | awk -F/ '{print $3}' \
    | grep -v '^$' \
    | sort \
    | uniq -c \
    | sort -rn \
    | head -10