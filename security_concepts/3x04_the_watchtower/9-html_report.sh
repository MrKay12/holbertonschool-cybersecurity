#!/bin/bash

TOP_ATTACKERS=$(grep "Failed password" "$1" \
| grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
| sort \
| uniq -c \
| sort -nr \
| head -5)

{
    echo '<!DOCTYPE html>'
    echo '<html>'
    echo '<head>'
    echo '<meta charset="UTF-8">'
    echo '<title>Security Report</title>'
    echo '</head>'
    echo '<body>'
    echo '<h1>Security Report</h1>'
    echo '<table border="1">'
    echo '<tr><th>Attempts</th><th>IP Address</th></tr>'

    echo "$TOP_ATTACKERS" | awk '{
        print "<tr><td>" $1 "</td><td>" $2 "</td></tr>"
    }'

    echo '</table>'
    echo '</body>'
    echo '</html>'
} > $2