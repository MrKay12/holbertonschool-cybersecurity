#!/bin/bash

set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 <proxy_ip>"
    exit 1
fi

curl -x "http://$1:3128" -o /dev/null -s -w "%{http_code}" http://malware.com
echo