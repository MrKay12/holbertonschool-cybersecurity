#!/bin/bash
awk -F: '($3<1000)&&($1!="root")&&($7~/sh$/){print $1}' "$1"
