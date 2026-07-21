#!/bin/bash

set -e

if [ "$EUID" -ne 0 ]; then
    echo "Error: this script must be run as root."
    exit 1
fi

nft add rule inet filter input ip saddr 10.200.0.0/24 tcp dport 3128 accept