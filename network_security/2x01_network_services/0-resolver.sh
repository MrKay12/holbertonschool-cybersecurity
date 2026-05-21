#!/bin/bash

resolver=$(awk '/^nameserver/ {print $2; exit}' /etc/resolv.conf)

if [ -z "$resolver" ] || [[ "$resolver" == "127.0.0.53" ]]; then
    resolver=$(resolvectl status 2>/dev/null | awk '/DNS Servers:/ {print $3; exit}')
fi

echo "$resolver"