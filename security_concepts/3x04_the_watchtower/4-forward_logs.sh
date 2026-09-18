#!/bin/bash

CONFIG="/etc/rsyslog.d/50-default.conf"

# Forward all logs to 127.0.0.1 using UDP
echo '*.* @127.0.0.1:514' >> "$CONFIG"

# Restart rsyslog
systemctl restart rsyslog

# Generate a test log message
logger "Test Log Forwarding"