#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 /etc/passwd"
  exit 1
fi

PASSWD_FILE="$1"

awk -F: '($3 == 0) && ($1 != "root") { print $1 }' "$PASSWD_FILE"
