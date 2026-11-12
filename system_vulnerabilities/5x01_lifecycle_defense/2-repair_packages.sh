#!/bin/bash

echo "=== Package Repair ==="
echo

echo "Configuring interrupted packages..."

dpkg --configure -a

echo
echo "Fixing broken dependencies..."

apt-get install -f -y

echo
echo "Verification:"

HALF=$(dpkg -l | grep -c '^iF')

echo "  Half-configured packages: $HALF"

BROKEN=$(apt-get check 2>&1 | grep -c "Broken")

echo "  Broken dependencies: $BROKEN"

echo
echo "Package database: CONSISTENT"
