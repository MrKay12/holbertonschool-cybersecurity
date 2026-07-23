#!/bin/bash

set -e

LOG_FILE="/var/log/squid/access.log"

awk '$4 ~ /403/ { print $1, $3, $8 }' "$LOG_FILE"