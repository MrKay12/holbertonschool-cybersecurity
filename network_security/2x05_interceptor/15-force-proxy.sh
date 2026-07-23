#!/bin/bash

set -e

VPN_SUBNET="10.200.0.0/24"
OUT_INTERFACE="$1"

if [ "$EUID" -ne 0 ]; then
    echo "Error: this script must be run as root."
    exit 1
fi

if [ $# -ne 1 ]; then
    echo "Usage: $0 <output_interface>"
    exit 1
fi

# Block VPN clients from accessing HTTP and HTTPS directly.
nft add rule inet filter forward \
    ip saddr "$VPN_SUBNET" \
    oifname "$OUT_INTERFACE" \
    tcp dport 80 drop

nft add rule inet filter forward \
    ip saddr "$VPN_SUBNET" \
    oifname "$OUT_INTERFACE" \
    tcp dport 443 drop

# Allow the proxy server itself to establish outbound HTTP/HTTPS connections.
nft add rule inet filter output \
    oifname "$OUT_INTERFACE" \
    tcp dport 80 accept

nft add rule inet filter output \
    oifname "$OUT_INTERFACE" \
    tcp dport 443 accept