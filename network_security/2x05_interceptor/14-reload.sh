#!/bin/bash

set -e

CONFIG="/etc/squid/squid.conf"

if ! squid -k parse -f "$CONFIG"; then
    exit 1
fi

squid -k reconfigure