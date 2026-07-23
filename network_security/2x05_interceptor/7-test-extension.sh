#!/bin/bash

set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 <proxy_ip>"
    exit 1
fi

http_code=$(curl -x "http://$1:3128" \
    -o /dev/null \
    -s \
    -w "%{http_code}" \
    http://example.com/test.exe)

echo "$http_code"

if [ "$http_code" -ne 403 ]; then
    exit 1
fi