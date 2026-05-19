#!/bin/bash
n=$1; for i in 1 2 3 4; do [ $n -ge 8 ] && o=255 || { [ $n -le 0 ] && o=0 || o=$((256-2**(8-n))); }; printf "%d" $o; [ $i -lt 4 ] && printf "."; n=$((n-8)); done