#!/bin/bash
ip addr | grep inet | grep tun0 | awk '{print $2}' | cut -d/ -f1