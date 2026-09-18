#!/bin/bash

INPUT="$1"
OUTPUT="$2"

TOP_ATTACKERS=$(grep "Failed password" "$INPUT" \
| grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
| sort \
| uniq -c \
| sort -nr \
| head -5)

{
    echo '<!DOCTYPE html>'
    echo '<html>'
    echo '<head>'
    echo '    <meta charset="UTF-8">'
    echo '    <title>Security Report</title>'
    echo '</head>'
    echo '<body>'
    echo '    <h1>Security Report</h1>'
    echo '    <table border="1">'
    echo '        <tr>'
    echo '            <th>Attempts</th>'
    echo '            <th>IP Address</th>'
    echo '        </tr>'

    echo "$TOP_ATTACKERS" | awk '{
        print "        <tr>"
        print "            <td>" $1 "</td>"
        print "            <td>" $2 "</td>"
        print "        </tr>"
    }'

    echo '    </table>'
    echo '</body>'
    echo '</html>'
} > "$OUTPUT"