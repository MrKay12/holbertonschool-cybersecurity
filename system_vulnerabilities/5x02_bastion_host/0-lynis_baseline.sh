#!/bin/bash
# 0-lynis_baseline.sh
# Run a Lynis audit and extract the hardening index and critical findings
# to establish a security baseline before hardening.

REPORT="/var/log/lynis-report.dat"
LOGFILE="/var/log/lynis.log"
OUTDIR="/var/log/hardening"
BASELINE="$OUTDIR/baseline-$(date +%Y%m%d).txt"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run as root (sudo $0)" >&2
    exit 1
fi

if ! command -v lynis >/dev/null 2>&1; then
    echo "Error: lynis is not installed (apt install lynis)" >&2
    exit 1
fi

mkdir -p "$OUTDIR"

echo "Running Lynis audit..."
lynis audit system --quick --quiet --no-colors \
    --report-file "$REPORT" --logfile "$LOGFILE" >/dev/null 2>&1

if [ ! -s "$REPORT" ]; then
    echo "Error: Lynis report not found at $REPORT" >&2
    exit 1
fi

INDEX=$(grep -m1 '^hardening_index=' "$REPORT" | cut -d= -f2)
TESTS=$(grep -m1 '^lynis_tests_done=' "$REPORT" | cut -d= -f2)
WARNINGS=$(grep -c '^warning\[\]=' "$REPORT")
SUGGESTIONS=$(grep -c '^suggestion\[\]=' "$REPORT")
INDEX=${INDEX:-0}
TESTS=${TESTS:-0}

# 20-char progress bar: one '#' per 5 points
FILLED=$((INDEX / 5))
BAR="$(printf '%*s' "$FILLED" '' | tr ' ' '#')$(printf '%*s' "$((20 - FILLED))" '' | tr ' ' '.')"

# warning[]=TEST-ID|message|details|solution|
FINDINGS=$(grep '^warning\[\]=' "$REPORT" | cut -d'|' -f2,3 |
    awk -F'|' '{ d = ($2 != "" && $2 != "-") ? ": " $2 : ""; print "  [WARNING] " $1 d }')

{
    echo
    echo "Hardening Index: $INDEX [$BAR]"
    echo "Tests Performed: $TESTS"
    echo "Warnings: $WARNINGS"
    echo "Suggestions: $SUGGESTIONS"
    echo
    echo "Critical Findings:"
    if [ -n "$FINDINGS" ]; then
        echo "$FINDINGS"
    else
        echo "  None"
    fi
} | tee "$BASELINE"

# Keep the full raw report with the baseline for later comparison
cp "$REPORT" "$OUTDIR/baseline-$(date +%Y%m%d).dat"

echo
echo "Baseline saved to: $BASELINE"
