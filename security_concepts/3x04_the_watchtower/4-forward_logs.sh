#!/bin/bash

# Forward all logs to 127.0.0.1 using UDP
echo '*.* @127.0.0.1:514' >> /etc/rsyslog.d/50-default.conf

# Restart rsyslog
systemctl restart rsyslog

# Generate the required test log message
logger "Test Log Forwarding"