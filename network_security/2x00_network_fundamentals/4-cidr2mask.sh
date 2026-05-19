#!/bin/bash
for i in 1 2 3 4; do
  if [ $1 -ge 8 ]; then
    printf "255"
    ((1-=8))
  else
    printf "%d" $((256 - 2**(8-$1)))
    1=0
  fi
  [ $i -lt 4 ] && printf "."
done
echo