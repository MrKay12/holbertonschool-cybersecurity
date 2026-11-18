#!/bin/bash
# 4-rp_filter.sh
# Enable strict reverse path filtering (rp_filter=1) and make it persistent.

CONF="/etc/sysctl.d/99-hardening.conf"
KEYS="net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run as root (sudo $0)" >&2
    exit 1
fi

touch "$CONF"

echo "=== Enabling Reverse Path Filtering ==="
echo
echo "Setting strict mode (1) for all interfaces..."
for k in $KEYS; do
    echo "  $(sysctl -w "$k=1")"
    if grep -q "^[[:space:]]*$k[[:space:]]*=" "$CONF"; then
        sed -i "s|^[[:space:]]*$k[[:space:]]*=.*|$k = 1|" "$CONF"
    else
        echo "$k = 1" >> "$CONF"
    fi
done

echo
echo "Configuration saved to $CONF"
echo

STRICT=1
for k in $KEYS; do
    [ "$(sysctl -n "$k")" = "1" ] || STRICT=0
done

if [ "$STRICT" -eq 1 ]; then
    echo "Reverse path filtering: STRICT MODE"
    echo "Spoofed packets will be dropped."
else
    echo "Reverse path filtering: NOT STRICT"
    exit 1
fi
