#!/bin/bash

# Flush all nftables rules
nft flush ruleset

# Set default policies to ACCEPT
nft add table inet filter

nft add chain inet filter input \
    "{ type filter hook input priority 0; policy accept; }"

nft add chain inet filter forward \
    "{ type filter hook forward priority 0; policy accept; }"

nft add chain inet filter output \
    "{ type filter hook output priority 0; policy accept; }"

echo "$(realpath "$0")" | at now + 5 minutes