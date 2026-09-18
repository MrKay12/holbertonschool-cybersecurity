#!/bin/bash

grep -i "sqlmap" "$1" | awk '{
    ip=$1
    method=$6
    gsub(/"/, "", method)

    path=""
    for (i=7; i<=NF; i++) {
        if ($i ~ /^HTTP\/[0-9.]+"/) {
            break
        }
        if (path == "")
            path=$i
        else
            path=path " " $i
    }

    print ip "," method "," path
}'