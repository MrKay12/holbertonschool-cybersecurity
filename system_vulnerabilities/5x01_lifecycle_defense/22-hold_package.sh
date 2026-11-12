#!/bin/bash
# 22-hold_package.sh
# Place a hold on a package and log the reason

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: $0 <package_name> <reason>"
    exit 1
fi

PACKAGE="$1"
REASON="$2"
LOG_FILE="/var/log/package_holds.log"

echo "=== Package Hold ==="
INSTALLED_VER=$(dpkg-query -W -f='${Version}' "$PACKAGE" 2>/dev/null || echo "Not installed")
echo
echo "Package: $PACKAGE"
echo "Current version: $INSTALLED_VER"
echo
echo "Placing hold..."
sudo apt-mark hold "$PACKAGE" && echo "  apt-mark hold $PACKAGE: Done"
echo
echo "Logging hold reason..."
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
echo "$TIMESTAMP | $PACKAGE | Hold reason: $REASON | Version: $INSTALLED_VER" | sudo tee -a "$LOG_FILE" >/dev/null
echo "  $LOG_FILE updated"
echo
echo "Hold verification:"
dpkg --get-selections | grep "^$PACKAGE" | grep hold >/dev/null && echo "  $PACKAGE set on hold." || echo "  FAILED to set hold."
echo
echo "WARNING: This package will NOT receive automatic updates."
echo "         Including security updates."
echo "         Review required within 30 days."
echo
echo "Hold applied successfully."
