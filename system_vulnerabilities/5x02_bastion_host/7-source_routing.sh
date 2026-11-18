#!/bin/bash
# 7-source_routing.sh
# Block source-routed packets (IPv4 and IPv6) and make it persistent.

CONF="/etc/sysctl.d/99-hardening.conf"
KEYS="net.ipv4.conf.all.accept_source_route net.ipv4.conf.default.accept_source_route net.ipv6.conf.all.accept_source_route net.ipv6.conf.default.accept_source_route"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run as root (sudo $0)" >&2
    exit 1
fi

touch "$CONF"

echo "=== Blocking Source Routing ==="
echo
echo "Disabling source route acceptance..."
for k in $KEYS; do
    echo "  $(sysctl -w "$k=0")"
    if grep -q "^[[:space:]]*$k[[:space:]]*=" "$CONF"; then
        sed -i "s|^[[:space:]]*$k[[:space:]]*=.*|$k = 0|" "$CONF"
    else
        echo "$k = 0" >> "$CONF"
    fi
done

echo
echo "Configuration saved to $CONF"
echo

STATUS="BLOCKED"
for k in $KEYS; do
    [ "$(sysctl -n "$k")" = "0" ] || STATUS="NOT BLOCKED"
done
echo "Source-routed packets: $STATUS"
[ "$STATUS" = "BLOCKED" ]
