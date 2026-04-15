#!/bin/bash
lsof -iTCP:$1 -sTCP:LISTEN -F -n -P 2>/dev/null | awk 'NR==2 {print substr($0,2); exit}' | xargs -r basename