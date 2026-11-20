#!/bin/bash
# 8-verify_kernel.sh
# Verify that all kernel hardening parameters are active and persistent.

CONF="/etc/sysctl.d/99-hardening.conf"
PASS=0
TOTAL=0

# check KEY EXPECTED: compare the live value with the expected one
check() {
    TOTAL=$((TOTAL + 1))
    val=$(sysctl -n "$1" 2>/dev/null)
    if [ "$val" = "$2" ]; then
        echo "  [PASS] $1 = $val"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] $1 = ${val:-missing} (expected $2)"
    fi
}

# result OK MESSAGE: record a generic check
result() {
    TOTAL=$((TOTAL + 1))
    if [ "$1" -eq 0 ]; then
        echo "  [PASS] $2"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] $2"
    fi
}

echo "=== Kernel Hardening Verification ==="
echo
echo "IP Forwarding:"
check net.ipv4.ip_forward 0
check net.ipv6.conf.all.forwarding 0

echo
echo "ICMP Redirects:"
check net.ipv4.conf.all.accept_redirects 0
check net.ipv4.conf.all.send_redirects 0

echo
echo "Reverse Path Filtering:"
check net.ipv4.conf.all.rp_filter 1

echo
echo "SYN Cookies:"
check net.ipv4.tcp_syncookies 1

echo
echo "Source Routing:"
check net.ipv4.conf.all.accept_source_route 0

echo
echo "ICMP Configuration:"
check net.ipv4.icmp_echo_ignore_broadcasts 1

echo
echo "Persistence Check:"
[ -f "$CONF" ]
result $? "$CONF exists"

# Every parameter above must be written in the config file
MISSING=0
for k in net.ipv4.ip_forward net.ipv6.conf.all.forwarding \
         net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects \
         net.ipv4.conf.all.rp_filter net.ipv4.tcp_syncookies \
         net.ipv4.conf.all.accept_source_route net.ipv4.icmp_echo_ignore_broadcasts; do
    grep -q "^[[:space:]]*$k[[:space:]]*=" "$CONF" 2>/dev/null || MISSING=1
done
result $MISSING "All parameters persisted in $CONF"

# The file must load cleanly at boot
sysctl -p "$CONF" >/dev/null 2>&1
result $? "$CONF loads without errors"

echo
echo "Summary: $PASS/$TOTAL checks passed"
if [ "$PASS" -eq "$TOTAL" ]; then
    echo "Kernel hardening: COMPLETE"
else
    echo "Kernel hardening: INCOMPLETE"
    exit 1
fi
