#!/bin/bash
IFS=' .'; read -r a b c d e f g h <<< "$1 $2"; printf "%d.%d.%d.%d" $((a|255-e)) $((b|255-f)) $((c|255-g)) $((d|255-h))