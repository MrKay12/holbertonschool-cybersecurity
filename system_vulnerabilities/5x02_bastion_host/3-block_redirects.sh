#!/bin/bash
# 3-block_redirects.sh
# Disable ICMP redirect acceptance and sending, and make it persistent.

CONF="/etc/sysctl.d/99-hardening.conf"
ACCEPT_KEYS="net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects net.ipv6.conf.all.accept_redirects net.ipv6.conf.default.accept_redirects"
SEND_KEYS="net.ipv4.conf.all.send_redirects net.ipv4.conf.default.send_redirects"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run as root (sudo $0)" >&2
    exit 1
fi

touch "$CONF"

# Set a key to 0 at runtime and persist it in $CONF (no duplicates)
set_zero() {
    echo "  $(sysctl -w "$1=0")"
    if grep -q "^[[:space:]]*$1[[:space:]]*=" "$CONF"; then
        sed -i "s|^[[:space:]]*$1[[:space:]]*=.*|$1 = 0|" "$CONF"
    else
        echo "$1 = 0" >> "$CONF"
    fi
}

echo "=== Blocking ICMP Redirects ==="
echo
echo "Disabling redirect acceptance..."
for k in $ACCEPT_KEYS; do
    set_zero "$k"
done

echo
echo "Disabling redirect sending..."
for k in $SEND_KEYS; do
    set_zero "$k"
done

echo
echo "Configuration saved to $CONF"
echo

STATUS="BLOCKED"
for k in $ACCEPT_KEYS $SEND_KEYS; do
    [ "$(sysctl -n "$k")" = "0" ] || STATUS="NOT BLOCKED"
done
echo "ICMP redirects: $STATUS"
