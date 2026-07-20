#!/bin/bash

# Enable IPv4 forwarding immediately
sysctl -w net.ipv4.ip_forward=1

# Make it persistent
if grep -q "^net.ipv4.ip_forward" /etc/sysctl.conf; then
    sed -i 's/^net\.ipv4\.ip_forward.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf
else
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi