#!/bin/bash
# 13-suid_audit.sh
# Find and categorize every SUID and SGID binary on the system.
#   KNOWN SAFE          - standard binaries that need the bit to work
#   REVIEW NEEDED       - from a distro package, but the bit may be removable
#   UNKNOWN - HIGH RISK - not owned by any package (custom / planted)

OUTDIR="/var/log/hardening"
REPORT="$OUTDIR/suid_audit.txt"

SAFE="sudo passwd chsh chfn gpasswd su unix_chkpwd ssh-agent ssh-keysign expiry chage crontab dotlockfile polkit-agent-helper-1 dbus-daemon-launch-helper"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run as root (sudo $0)" >&2
    exit 1
fi

# category FILE: print the risk category of a binary
category() {
    case " $SAFE " in
        *" $(basename "$1") "*) echo "KNOWN SAFE"; return ;;
    esac
    # usr-merge: /usr/bin/x may be registered by dpkg as /bin/x
    alt=${1#/usr}
    if dpkg -S "$1" >/dev/null 2>&1 || dpkg -S "$alt" >/dev/null 2>&1; then
        echo "REVIEW NEEDED"
    else
        echo "UNKNOWN - HIGH RISK"
    fi
}

# Virtual / irrelevant filesystems to skip
PRUNE='( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /snap -o -path /var/lib/docker ) -prune -o'

# List SUID binaries
scan_suid() {
    find / $PRUNE -type f -perm -4000 -print 2>/dev/null | sort
}

# List SGID binaries
scan_sgid() {
    find / $PRUNE -type f -perm -2000 -print 2>/dev/null | sort
}

mkdir -p "$OUTDIR"

{
    echo "=== SUID/SGID Binary Audit ==="
    echo
    echo "SUID binaries (run as owner):"
    while IFS= read -r f; do
        cat=$(category "$f")
        printf "  %-29s %-8s %s\n" "$f" "$(stat -c '%U' "$f")" "$cat"
    done < <(scan_suid)
    echo
    echo "SGID binaries (run as group):"
    while IFS= read -r f; do
        cat=$(category "$f")
        printf "  %-29s %-8s %s\n" "$f" "$(stat -c '%G' "$f")" "$cat"
    done < <(scan_sgid)
} > "$REPORT.tmp"

SUID_COUNT=$(sed -n '/^SUID/,/^$/p' "$REPORT.tmp" | grep -c '^  /')
SGID_COUNT=$(sed -n '/^SGID/,$p' "$REPORT.tmp" | grep -c '^  /')
UNKNOWN=$(grep -c 'UNKNOWN - HIGH RISK' "$REPORT.tmp")

{
    cat "$REPORT.tmp"
    echo
    echo "Summary:"
    echo "  Total SUID: $SUID_COUNT"
    echo "  Total SGID: $SGID_COUNT"
    echo "  Unknown/Custom: $UNKNOWN (requires investigation)"
} > "$REPORT"
rm -f "$REPORT.tmp"

cat "$REPORT"
echo
echo "Full report saved to: $REPORT"
