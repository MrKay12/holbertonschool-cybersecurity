#!/bin/bash

IP="$1"
PID="$2"

iptables -A INPUT -s "$IP" -j DROP
iptables -A OUTPUT -d "$IP" -j DROP

kill -STOP "$PID"