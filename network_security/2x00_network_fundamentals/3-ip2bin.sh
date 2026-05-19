#!/bin/bash
printf "%08d.%08d.%08d.%08d\n" $(echo "$1" | tr '.' ' ' | xargs -n1 -I{} bash -c 'echo "obase=2;{}" | bc')