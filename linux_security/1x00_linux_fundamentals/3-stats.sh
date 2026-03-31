#!/bin/bash
ls -l "$1" | awk '{print $3}' | sort | uniq -c | sort -nr | head -1 | awk '{print $2}'
