#!/bin/bash
lsof -n -iTCP:$1 -sTCP:LISTEN | awk 'NR>1 {print $1}'