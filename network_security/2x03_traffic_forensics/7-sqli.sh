#!/bin/bash
tshark -r "$1" -T fields -e http.request.uri | while read -r uri
do
    decoded=$(python3 -c "import urllib.parse,sys; print(urllib.parse.unquote(sys.argv[1]))" "$uri")
    echo "$decoded" | grep -Eiq "UNION|SELECT" && echo "$uri"
done