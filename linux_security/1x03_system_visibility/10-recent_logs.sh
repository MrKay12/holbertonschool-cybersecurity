#!/bin/bash
since=$(date --date="30 minutes ago" "+%b %e %H:%M:%S")
awk -v since="$since" '$0 ~ /sshd/ && $0 >= since' "$1"