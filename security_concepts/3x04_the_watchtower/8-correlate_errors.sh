#!/bin/bash

awk '$9 ~ /^4[0-9][0-9]$/ {count[$1]++}
END {
    for (ip in count) {
        if (count[ip] > 5) {
            print "ALERT: IP " ip " is scanning us!"
        }
    }
}' "$1"