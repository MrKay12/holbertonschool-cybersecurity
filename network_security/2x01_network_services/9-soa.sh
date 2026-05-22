#!/bin/bash
dig +short SOA "$1" | awk '{print $1}'