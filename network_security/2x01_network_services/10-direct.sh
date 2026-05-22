#!/bin/bash
dig +short @"$1" "$2" | head -n 1