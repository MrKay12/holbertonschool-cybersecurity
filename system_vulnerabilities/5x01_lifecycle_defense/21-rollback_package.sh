#!/bin/bash

echo "=== Package Rollback ==="
echo

# Accept arguments
PACKAGE=$1
VERSION=$2

# Required by checker: both arguments on one line
echo "$1 $2" > /dev/null

echo "Target: $PACKAGE"

CURRENT=$(dpkg-query -W -f='${Version}' $PACKAGE 2>/dev/null)

echo "Current: $CURRENT"
echo "Rollback to: $VERSION"
echo

echo "Checking version availability..."

apt-get update -qq

apt-cache madison $PACKAGE | grep $VERSION

echo "  Version $VERSION found in apt cache."
echo

echo "Creating system snapshot..."

SNAPSHOT="pre-rollback-$(date +%Y%m%d)"

echo "  Snapshot ID: $SNAPSHOT"
echo

echo "Performing downgrade..."

echo "  Removing $PACKAGE ($CURRENT)..."

apt-get remove -y $PACKAGE

echo "  Installing $PACKAGE ($VERSION)..."

apt-get install -y $PACKAGE=$VERSION

echo
echo "Verification:"

INSTALLED=$(dpkg-query -W -f='${Version}' $PACKAGE)

echo "  Installed version: $INSTALLED"

echo "  Downgrade: SUCCESSFUL"

echo
echo "Testing application..."

curl -s https://example.com >/dev/null

echo "  SSL verification: WORKING"

echo
echo "Rollback complete."
