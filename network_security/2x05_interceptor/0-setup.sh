#!/bin/bash

set -e

SQUID_CONFIG="/etc/squid/squid.conf"
SQUID_BACKUP="/etc/squid/squid.conf.bak"

if [ "$EUID" -ne 0 ]; then
    echo "Error: this script must be run as root."
    exit 1
fi

apt-get update -y
apt-get install -y squid

systemctl stop squid
systemctl enable squid

if [ ! -f "$SQUID_CONFIG" ]; then
    echo "Error: Squid configuration file not found."
    exit 1
fi

if [ ! -f "$SQUID_BACKUP" ]; then
    cp -p "$SQUID_CONFIG" "$SQUID_BACKUP"
fi