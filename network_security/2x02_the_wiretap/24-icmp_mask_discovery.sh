#!/bin/bash

[ "$EUID" -ne 0 ] && exit 1

nmap -sn -PM "$1"