#!/bin/bash
ss -ltnp | grep ":$1 " | awk '{print $6}' | cut -d'"' -f2