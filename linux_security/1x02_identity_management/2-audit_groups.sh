#!/bin/bash
awk -F: 'NR==FNR && $3>=1000 {users[$1]; next} $1~/^(disk|docker|shadow)$/ {for(i=4;i<=NF;i++) if($i in users) print $i ":" $1}' "$1" /etc/group
