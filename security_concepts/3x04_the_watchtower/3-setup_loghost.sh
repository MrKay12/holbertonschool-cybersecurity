#!/bin/bash

CONFIG="/etc/rsyslog.conf"
BACKUP="/etc/rsyslog.conf.bak"

# Backup configuration
cp "$CONFIG" "$BACKUP"

# Enable UDP reception on port 514
sed -i 's/^#module(load="imudp")/module(load="imudp")/' "$CONFIG"
sed -i 's/^#input(type="imudp" port="514")/input(type="imudp" port="514")/' "$CONFIG"

# Enable TCP reception on port 514
sed -i 's/^#module(load="imtcp")/module(load="imtcp")/' "$CONFIG"
sed -i 's/^#input(type="imtcp" port="514")/input(type="imtcp" port="514")/' "$CONFIG"

# Restart rsyslog
systemctl restart rsyslog