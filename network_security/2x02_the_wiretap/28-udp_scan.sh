#!/bin/bash

[ "$EUID" -ne 0 ] && exit 1

sudo nmap -sU -p 53,161 "$1"