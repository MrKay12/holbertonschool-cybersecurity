#!/bin/bash
# 18-harden_other_tmp.sh
# Harden /var/tmp (bind mount to /tmp) and /dev/shm (noexec,nosuid,nodev),
# both at runtime and persistently in /etc/fstab.

FSTAB="/etc/fstab"
VARTMP_LINE="/tmp /var/tmp none rw,noexec,nosuid,nodev,bind 0 0"
SHM_LINE="tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run as root (sudo $0)" >&2
    exit 1
fi

# set_fstab MOUNTPOINT LINE: add or replace the fstab entry for a mount point
set_fstab() {
    if grep -qE "^[^#]*[[:space:]]$1[[:space:]]" "$FSTAB"; then
        sed -i -E "s|^[^#]*[[:space:]]$1[[:space:]].*|$2|" "$FSTAB"
        echo "  Updated in $FSTAB"
    else
        echo "$2" >> "$FSTAB"
        echo "  Added to $FSTAB"
    fi
}

# has_all MOUNTPOINT: true if mounted with noexec, nosuid and nodev
has_all() {
    o=$(findmnt -n -o OPTIONS "$1")
    echo "$o" | grep -qw noexec && echo "$o" | grep -qw nosuid && echo "$o" | grep -qw nodev
}

cp "$FSTAB" "$FSTAB.bak.$(date +%Y%m%d%H%M%S)"

echo "=== Hardening /var/tmp and /dev/shm ==="
echo
echo "Hardening /var/tmp..."
echo "  Bind mount to /tmp (inherits restrictions)"
set_fstab /var/tmp "$VARTMP_LINE"

echo
echo "Hardening /dev/shm..."
CUR=$(findmnt -n -o FSTYPE,OPTIONS /dev/shm)
echo "  Current: $(echo "$CUR" | awk '{print $1}') ($(echo "$CUR" | awk '{print $2}' | tr ',' '\n' | grep -E '^(rw|ro|nosuid|nodev|noexec)$' | paste -sd,))"
MISSING=""
for opt in noexec nosuid nodev; do
    echo "$CUR" | grep -qw "$opt" || MISSING="$MISSING,$opt"
done
[ -n "$MISSING" ] && echo "  Adding: ${MISSING#,}"
set_fstab /dev/shm "$SHM_LINE"

echo
echo "Remounting..."
mountpoint -q /var/tmp || mount --bind /tmp /var/tmp
# A bind mount needs a remount to apply its own restrictions
mount -o remount,bind,noexec,nosuid,nodev /var/tmp
mount -o remount,noexec,nosuid,nodev /dev/shm
systemctl daemon-reload 2>/dev/null

echo
echo "Verification:"
OK=1
for m in /var/tmp /dev/shm; do
    if has_all "$m"; then
        echo "  $m: noexec,nosuid,nodev ✓"
    else
        echo "  $m: $(findmnt -n -o OPTIONS "$m") ✗"
        OK=0
    fi
done

echo
if [ "$OK" -eq 1 ]; then
    echo "All temporary directories hardened."
else
    echo "Hardening incomplete."
    exit 1
fi
