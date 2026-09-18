#!/bin/bash

# JSON fields: "time" "host" "msg"
cat >> /etc/rsyslog.conf << 'EOF'
$template json_fmt,"{\"time\":\"%timestamp%\", \"host\":\"%hostname%\", \"msg\":\"%msg%\"}"
EOF