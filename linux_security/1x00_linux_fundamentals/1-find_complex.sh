#!/bin/bash
find "$1" -type f -size +1M -mtime -1 ! -name "*.gz" 2>/dev/null
