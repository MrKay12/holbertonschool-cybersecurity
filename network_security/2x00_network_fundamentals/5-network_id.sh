#!/bin/bash
IFS=. read a b c d e f g h <<< "${1//./ } ${2//./ }"; printf "%d.%d.%d.%d" $((a&e)) $((b&f)) $((c&g)) $((d&h))