#!/bin/bash
# 23-final_audit.sh
# Run a final Lynis audit and compare it with the baseline from 0-lynis_baseline.sh.

REPORT="/var/log/lynis-report.dat"
LOGFILE="/var/log/lynis.log"
OUTDIR="/var/log/hardening"
FINAL="$OUTDIR/final-$(date +%Y%m%d).txt"
MAX_SUGGESTIONS=5

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run as root (sudo $0)" >&2
    exit 1
fi

if ! command -v lynis >/dev/null 2>&1; then
    echo "Error: lynis is not installed (apt install lynis)" >&2
    exit 1
fi

# Latest baseline produced by 0-lynis_baseline.sh
BASELINE=$(ls -1t "$OUTDIR"/baseline-*.txt 2>/dev/null | head -1)

mkdir -p "$OUTDIR"

# 20-char bar: one '#' per 5 points
bar() {
    f=$(($1 / 5))
    printf '%s%s' "$(printf '%*s' "$f" '' | tr ' ' '#')" "$(printf '%*s' "$((20 - f))" '' | tr ' ' '.')"
}

# delta OLD NEW: signed difference
delta() {
    d=$(($2 - $1))
    [ "$d" -ge 0 ] && echo "+$d" || echo "$d"
}

{
echo "=== Final Security Audit ==="
echo
echo "Running Lynis audit..."
lynis audit system --quick --quiet --no-colors \
    --report-file "$REPORT" --logfile "$LOGFILE" >/dev/null 2>&1

if [ ! -s "$REPORT" ]; then
    echo "Error: Lynis report not found at $REPORT" >&2
    exit 1
fi

INDEX=$(grep -m1 '^hardening_index=' "$REPORT" | cut -d= -f2)
TESTS=$(grep -m1 '^lynis_tests_done=' "$REPORT" | cut -d= -f2)
WARN=$(grep -c '^warning\[\]=' "$REPORT")
SUGG=$(grep -c '^suggestion\[\]=' "$REPORT")
INDEX=${INDEX:-0}

echo
echo "Results:"
echo "  Hardening Index: $INDEX [$(bar "$INDEX")]"
echo "  Tests Performed: ${TESTS:-0}"
echo "  Warnings: $WARN"
echo "  Suggestions: $SUGG"

echo
echo "Comparison with baseline:"
if [ -n "$BASELINE" ]; then
    B_INDEX=$(grep -m1 '^Hardening Index:' "$BASELINE" | awk '{print $3}')
    B_WARN=$(grep -m1 '^Warnings:' "$BASELINE" | awk '{print $2}')
    B_SUGG=$(grep -m1 '^Suggestions:' "$BASELINE" | awk '{print $2}')
    B_INDEX=${B_INDEX:-0}; B_WARN=${B_WARN:-0}; B_SUGG=${B_SUGG:-0}
    GAIN=$((INDEX - B_INDEX))
    echo "  Hardening Index: $B_INDEX → $INDEX ($(delta "$B_INDEX" "$INDEX") points)"
    echo "  Warnings: $B_WARN → $WARN ($(delta "$WARN" "$B_WARN" | sed 's/^+/-/;t;s/^-/+/') resolved)"
    echo "  Suggestions: $B_SUGG → $SUGG ($(delta "$SUGG" "$B_SUGG" | sed 's/^+/-/;t;s/^-/+/') resolved)"
else
    GAIN=0
    echo "  No baseline found in $OUTDIR (run 0-lynis_baseline.sh first)"
fi

echo
echo "Remaining items:"
# warning[]=TEST-ID|message|details|solution|
grep '^warning\[\]=' "$REPORT" | cut -d'|' -f2 | sed 's/^/  [WARNING] /'
grep '^suggestion\[\]=' "$REPORT" | cut -d'|' -f2 | head -n "$MAX_SUGGESTIONS" | sed 's/^/  [SUGGESTION] /'
[ "$SUGG" -gt "$MAX_SUGGESTIONS" ] && echo "  ... and $((SUGG - MAX_SUGGESTIONS)) more suggestions (see $REPORT)"
[ "$WARN" -eq 0 ] && [ "$SUGG" -eq 0 ] && echo "  None"

echo
if [ "$GAIN" -ge 15 ]; then
    echo "Summary: System hardened significantly."
    echo "Ready for DMZ deployment pending CISO review."
elif [ "$GAIN" -gt 0 ]; then
    echo "Summary: System partially hardened (+$GAIN points)."
    echo "Address remaining warnings before DMZ deployment."
else
    echo "Summary: No improvement measured."
    echo "Not ready for DMZ deployment."
fi
} | tee "$FINAL"

echo
echo "Final report saved to: $FINAL"
