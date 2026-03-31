#!/bin/bash
ls -al "$1" | awk '{print $3}' | sort | uniq -c | sort -nr | head -n 1 | awk '{print $2}'
