#!/bin/bash
tshark -r "$1" -Y 'http.request.uri matches "(?i)(UNION|SELECT)"' -T fields -e http.request.uri \done