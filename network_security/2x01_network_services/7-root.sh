#!/bin/bash
dig +trace "$1" | awk '/Received/ {n++; if(n==2){split($5,a,"#"); printf "%s",a[1]; exit}}'