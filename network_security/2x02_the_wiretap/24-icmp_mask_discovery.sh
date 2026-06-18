#!/bin/bash

[ "$EUID" -ne 0 ] && exit 1

sudo nmap -sn -PM "$1"