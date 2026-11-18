#!/bin/bash
# 6-icmp_config.sh
# Configure ICMP echo handling following the CIS benchmark:
#   - Ignore broadcast pings (Smurf attack prevention)
#   - Keep unicast ping enabled (blocking it adds little security
#     and makes network troubleshooting harder)
#   - Ignore bogus ICMP error responses (avoids log flooding)

CONF="/etc/sysctl.d/99-hardening.conf"
NOTE="# ICMP decision: broadcast ping disabled (Smurf), unicast ping kept for diagnostics (CIS)"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run as root (sudo $0)" >&2
    exit 1
fi

touch "$CONF"

# Set a key at runtime and persist it in $CONF (no duplicates)
set_key() {
    echo "  $(sysctl -w "$1=$2")"
    if grep -q "^[[:space:]]*$1[[:space:]]*=" "$CONF"; then
        sed -i "s|^[[:space:]]*$1[[:space:]]*=.*|$1 = $2|" "$CONF"
    else
        echo "$1 = $2" >> "$CONF"
    fi
}

# Document the decision in the config file (once)
grep -qF "$NOTE" "$CONF" || echo "$NOTE" >> "$CONF"

echo "=== ICMP Configuration ==="
echo
echo "Disabling broadcast ping response (Smurf prevention)..."
set_key net.ipv4.icmp_echo_ignore_broadcasts 1

echo
echo "Keeping unicast ping enabled for diagnostics."
set_key net.ipv4.icmp_echo_ignore_all 0

echo
echo "Ignoring bogus ICMP error responses..."
set_key net.ipv4.icmp_ignore_bogus_error_responses 1

echo
echo "Configuration saved to $CONF"
echo

[ "$(sysctl -n net.ipv4.icmp_echo_ignore_broadcasts)" = "1" ] && B="DISABLED" || B="ENABLED"
[ "$(sysctl -n net.ipv4.icmp_echo_ignore_all)" = "0" ] && U="ENABLED" || U="DISABLED"
echo "Broadcast ping: $B"
echo "Unicast ping: $U"
