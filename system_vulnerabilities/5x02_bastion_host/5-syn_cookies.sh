#!/bin/bash
# 5-syn_cookies.sh
# Enable TCP SYN cookies and make it persistent.

CONF="/etc/sysctl.d/99-hardening.conf"
KEY="net.ipv4.tcp_syncookies"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run as root (sudo $0)" >&2
    exit 1
fi

echo "=== Enabling SYN Cookies ==="
echo
echo "Current state:"
echo "  $(sysctl "$KEY")"

echo
echo "Enabling SYN cookies..."
echo "  $(sysctl -w "$KEY=1")"

touch "$CONF"
if grep -q "^[[:space:]]*$KEY[[:space:]]*=" "$CONF"; then
    sed -i "s|^[[:space:]]*$KEY[[:space:]]*=.*|$KEY = 1|" "$CONF"
else
    echo "$KEY = 1" >> "$CONF"
fi

echo
echo "Configuration saved to $CONF"
echo

if [ "$(sysctl -n "$KEY")" = "1" ]; then
    echo "SYN flood protection: ENABLED"
else
    echo "SYN flood protection: DISABLED"
    exit 1
fi
