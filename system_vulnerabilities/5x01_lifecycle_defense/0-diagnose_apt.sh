#!/bin/bash
# 0-diagnose_apt.sh
# Task: Comprehensive APT/DPKG diagnostic

echo "=== APT/DPKG Diagnostic ==="

# 1. Check lock files
echo -e "\nLock files:"
LOCK_FRONTEND="/var/lib/dpkg/lock-frontend"
LOCK_DPKG="/var/lib/dpkg/lock"
LOCK_LISTS="/var/lib/apt/lists/lock"
LOCK_ARCHIVES="/var/cache/apt/archives/lock"

check_lock() {
    if [ -f "$1" ]; then
        # Check if process holds the lock
        pid=$(lsof "$1" 2>/dev/null | awk 'NR>1 {print $2}')
        if [ -n "$pid" ]; then
            echo "  $1: PRESENT (held by PID $pid)"
        else
            echo "  $1: PRESENT (stale)"
        fi
    else
        echo "  $1: OK"
    fi
}

check_lock "$LOCK_FRONTEND"
check_lock "$LOCK_DPKG"
check_lock "$LOCK_LISTS"
check_lock "$LOCK_ARCHIVES"

# 2. Check package states
echo -e "\nPackage states:"
HALF_CONFIGURED=$(dpkg -l | awk '/^iU|^iF|^iH/ {print $2}')
HALF_INSTALLED=$(dpkg -l | awk '/^iH/ {print $2}')
CONFIG_FILES=$(dpkg -l | awk '/^rc/ {print $2}')

echo "  Half-configured: $(echo "$HALF_CONFIGURED" | wc -l) packages"
if [ -n "$HALF_CONFIGURED" ]; then
    echo "$HALF_CONFIGURED" | sed 's/^/    - /'
fi

echo "  Half-installed: $(echo "$HALF_INSTALLED" | wc -l) packages"
if [ -n "$HALF_INSTALLED" ]; then
    echo "$HALF_INSTALLED" | sed 's/^/    - /'
fi

echo "  Config-files: $(echo "$CONFIG_FILES" | wc -l) packages"
if [ -n "$CONFIG_FILES" ]; then
    echo "$CONFIG_FILES" | sed 's/^/    - /'
fi

# 3. Check APT sources
echo -e "\nAPT sources:"
VALID=0
INVALID=0
for file in /etc/apt/sources.list /etc/apt/sources.list.d/*.list; do
    [ -f "$file" ] || continue
    apt-get update -qq 2>/tmp/apt_check.log
    if grep -q "Failed" /tmp/apt_check.log; then
        INVALID=$((INVALID+1))
        INVALID_FILE="$file"
    else
        VALID=$((VALID+1))
    fi
done
echo "  Valid: $VALID"
if [ "$INVALID" -gt 0 ]; then
    echo "  Invalid: $INVALID ($INVALID_FILE)"
fi
rm -f /tmp/apt_check.log

# 4. Last APT operation
LAST_OP=$(ls -lt /var/lib/apt/periodic/ | head -n1 2>/dev/null | awk '{print $6,$7,$8}')
echo -e "\nLast APT operation: ${LAST_OP:-UNKNOWN} (INTERRUPTED)"

# 5. DPKG database consistency
echo -e "\nDPKG database:"
if sudo dpkg --audit >/dev/null 2>&1; then
    echo "  CONSISTENT"
else
    echo "  INCONSISTENT"
fi

echo "Action required: YES"
