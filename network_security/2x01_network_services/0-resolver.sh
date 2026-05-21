#!/bin/bash
awk '/^nameserver/ {print $2; exit}' /etc/resolv.conf