#!/bin/bash

# Create rsyslog rule for authpriv logs
echo 'authpriv.info /var/log/secure_remote.log' > /etc/rsyslog.d/60-auth.conf

# Restart rsyslog
systemctl restart rsyslog