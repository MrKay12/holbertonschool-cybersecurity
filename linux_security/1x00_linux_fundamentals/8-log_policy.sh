#!/bin/bash

chown root:$2 $1
chmod 2770 $1

echo "$1/*.log {
    daily
    rotate 7
    missingok
    notifempty
    compress
    create 0640 root $2
}" > /etc/logrotate.d/app