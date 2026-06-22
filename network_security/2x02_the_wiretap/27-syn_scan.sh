#!/bin/bash

[ "$EUID" -ne 0 ] && exit 1

nmap -sS -p 22,23,80 "$1"