#!/bin/bash
# 2-disable_forwarding.sh
# Disable IPv4/IPv6 forwarding at runtime and make it persistent.

CONF="/etc/sysctl.d/99-hardening.conf"
KEYS="net.ipv4.ip_forward net.ipv6.conf.all.forwarding"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run as root (sudo $0)" >&2
    exit 1
fi

echo "=== Disabling IP Forwarding ==="
echo
echo "Current state:"
for k in $KEYS; do
    echo "  $(sysctl "$k")"
done

echo
echo "Applying changes..."
for k in $KEYS; do
    echo "  $(sysctl -w "$k=0")"
done

echo
echo "Making persistent in $CONF..."
touch "$CONF"
for k in $KEYS; do
    if grep -q "^[[:space:]]*$k[[:space:]]*=" "$CONF"; then
        sed -i "s|^[[:space:]]*$k[[:space:]]*=.*|$k = 0|" "$CONF"
    else
        echo "$k = 0" >> "$CONF"
    fi
done

echo
echo "Verification:"
[ "$(sysctl -n net.ipv4.ip_forward)" = "0" ] && V4="DISABLED" || V4="ENABLED"
[ "$(sysctl -n net.ipv6.conf.all.forwarding)" = "0" ] && V6="DISABLED" || V6="ENABLED"
echo "  IPv4 forwarding: $V4"
echo "  IPv6 forwarding: $V6"
