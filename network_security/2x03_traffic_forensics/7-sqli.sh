#!/bin/bash
tshark -r "$1" -T fields -e http.request.uri | grep -Ei "union|select|%55%4e%49%4f%4e|%53%45%4c%45%43%54" \ndone