#!/bin/bash
lsof -n -P -iTCP:$1 -sTCP:LISTEN | awk 'NR>1 {print $1}'