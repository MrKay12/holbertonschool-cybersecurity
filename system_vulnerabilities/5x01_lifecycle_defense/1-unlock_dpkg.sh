#!/bin/bash
# 1-unlock_dpkg.sh
# Task: Safely remove stale lock files for dpkg/apt

echo "=== DPKG Unlock Procedure ==="

# 1. Check for active apt/dpkg processes using pgrep or ps
echo -e "\nChecking for active package operations..."
APT_PROC=$(pgrep -x apt || ps aux | grep -v grep | grep -w apt)
DPKG_PROC=$(pgrep -x dpkg || ps aux | grep -v grep | grep -w dpkg)

if [ -z "$APT_PROC" ]; then
    echo "  apt processes: None"
else
    echo "  apt processes: $APT_PROC"
fi

if [ -z "$DPKG_PROC" ]; then
    echo "  dpkg processes: None"
else
    echo "  dpkg processes: $DPKG_PROC"
fi

# 2. Only proceed if no processes are running
if [ -n "$APT_PROC" ] || [ -n "$DPKG_PROC" ]; then
    echo -e "\nActive package operation detected. Aborting unlock."
    exit 1
fi

# 3. Remove stale lock files
echo -e "\nRemoving stale lock files..."
LOCKS=(
    "/var/lib/dpkg/lock-frontend"
    "/var/lib/dpkg/lock"
    "/var/lib/apt/lists/lock"
    "/var/cache/apt/archives/lock"
)

for lock in "${LOCKS[@]}"; do
    if [ -f "$lock" ]; then
        # Check if lock is held by a process
        fuser "$lock" >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo "  $lock: In use by a process, skipping"
        else
            rm -f "$lock" && echo "  $lock: Removed" || echo "  $lock: Failed to remove"
        fi
    else
        echo "  $lock: Not present"
    fi
done

# 4. Verification step
echo -e "\nVerification:"
dpkg --audit >/dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "  Package operations: UNLOCKED"
    echo -e "\nDPKG unlocked successfully."
else
    echo "  Package operations: ISSUES DETECTED"
    echo -e "\nWarning: Check dpkg state with 'dpkg --audit'."
fi
