#!/bin/bash
# 20-identify_bad_update.sh
# Identify the package that caused a system issue based on timestamp

if [ -z "$1" ]; then
    echo "Usage: $0 <timestamp> (format: YYYY-MM-DD HH:MM)"
    exit 1
fi

TARGET_TIME="$1"
echo "=== Bad Update Identification ==="
echo "Searching for updates around: $TARGET_TIME"
echo

# Look into APT history logs
echo "Checking /var/log/apt/history.log..."
grep "$TARGET_TIME" /var/log/apt/history.log 2>/dev/null | awk '/Upgrade|Install|Remove/ {print "APT: "$0}'

# Look into dpkg logs
echo
echo "Checking /var/log/dpkg.log..."
grep "$TARGET_TIME" /var/log/dpkg.log 2>/dev/null | awk '/install|upgrade|remove/ {print "DPKG: "$0}'

# Suggest potential culprit package(s)
echo
echo "Analyzing logs to identify culprit package(s)..."
APT_PACKAGES=$(grep "$TARGET_TIME" /var/log/apt/history.log 2>/dev/null | awk '/Upgrade|Install/ {print $2}')
DPKG_PACKAGES=$(grep "$TARGET_TIME" /var/log/dpkg.log 2>/dev/null | awk '/install|upgrade/ {print $4}')

ALL_PACKAGES=$(echo -e "$APT_PACKAGES\n$DPKG_PACKAGES" | sort | uniq)

if [ -n "$ALL_PACKAGES" ]; then
    echo "Potential culprit package(s) installed/updated at $TARGET_TIME:"
    for pkg in $ALL_PACKAGES; do
        echo "  - $pkg"
    done
else
    echo "No packages found for the given timestamp."
fi
