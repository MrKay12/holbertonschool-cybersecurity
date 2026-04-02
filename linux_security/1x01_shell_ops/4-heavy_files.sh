#!/bin/bash
find ./ -type f -size +1024b 2>/dev/null && cat "$1" 2>/dev/null