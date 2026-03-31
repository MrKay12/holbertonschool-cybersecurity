#!/bin/bash
mkdir -p "$1" && chgrp "$2" "$1" && chmod 2775 "$1" && chmod +t "$1"