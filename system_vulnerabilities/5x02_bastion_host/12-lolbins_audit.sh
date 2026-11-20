#!/bin/bash
# 12-lolbins_audit.sh
# Audit commonly abused "Living off the Land" binaries (GTFOBins)
# and report their current permissions. Read-only: nothing is changed.

# check PATH NOTE: print permissions and a status for one binary.
# NOTE is empty when the binary is only risky with SUID/SGID.
check() {
    [ -e "$1" ] || return
    perms=$(stat -L -c '%A' "$1")
    mode=$(stat -L -c '%a' "$1")
    if [ "${#mode}" -eq 4 ] && [ $(( ${mode:0:1} & 6 )) -ne 0 ]; then
        status="CRITICAL: SUID/SGID set - privilege escalation"
    elif [ -n "$2" ]; then
        status="WARNING: $2"
    else
        status="OK"
    fi
    echo "  $1: $perms ($status)"
}

echo "=== Living off the Land Binaries Audit ==="
echo
echo "Checking GTFOBins candidates..."

echo
echo "File Readers (can read sensitive files):"
check /usr/bin/cat ""
check /usr/bin/less ""
check /usr/bin/vim "Can escape to shell"

echo
echo "Shell Escapes:"
check /usr/bin/python3 "Can spawn shells"
check /usr/bin/perl "Can spawn shells"
check /usr/bin/awk ""

echo
echo "Network Tools:"
check /usr/bin/wget "Can download payloads"
check /usr/bin/curl "Can download payloads"

echo
echo "Note: These binaries are legitimate but should be monitored."
echo "See https://gtfobins.github.io/ for abuse techniques."
