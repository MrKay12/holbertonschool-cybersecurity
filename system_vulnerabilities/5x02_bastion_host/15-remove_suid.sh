#!/bin/bash
# 15-remove_suid.sh
# Remove the SUID bit from every non-essential binary.
# Only sudo, passwd and su keep it (required for basic operation).

ESSENTIAL="/usr/bin/sudo /usr/bin/passwd /usr/bin/su"
ADMIN="mount umount fusermount fusermount3 mount.cifs mount.nfs ntfs-3g"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run as root (sudo $0)" >&2
    exit 1
fi

# List all SUID binaries, skipping virtual filesystems
list_suid() {
    find / \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o -type f -perm -4000 -print 2>/dev/null | sort
}

# reason FILE: why the SUID bit is removed
reason() {
    case " $ADMIN " in
        *" $(basename "$1") "*) echo "admin can use sudo"; return ;;
    esac
    alt=${1#/usr}
    if dpkg -S "$1" >/dev/null 2>&1 || dpkg -S "$alt" >/dev/null 2>&1; then
        echo "not needed"
    else
        echo "CUSTOM - HIGH RISK"
    fi
}

BEFORE=$(list_suid | wc -l)

echo "=== SUID Neutralization ==="
echo
echo "Preserving essential SUID (DO NOT TOUCH):"
for e in $ESSENTIAL; do
    echo "  $e"
done

echo
echo "Removing SUID from non-essential binaries..."
REMOVED=""
while IFS= read -r f; do
    case " $ESSENTIAL " in *" $f "*) continue ;; esac
    if chmod u-s "$f"; then
        echo "  $f: SUID removed ($(reason "$f"))"
        REMOVED="$REMOVED $f"
    else
        echo "  $f: FAILED to remove SUID"
    fi
done < <(list_suid)
[ -z "$REMOVED" ] && echo "  Nothing to remove"

echo
echo "Verification:"
for b in mount umount; do
    p=$(command -v "$b") || continue
    perms=$(stat -L -c '%A' "$p")
    case "$perms" in
        ???s*|???S*) echo "  $b: $perms (SUID STILL SET)" ;;
        *)           echo "  $b: $perms (no SUID)" ;;
    esac
done

AFTER=$(list_suid | wc -l)
echo
echo "SUID binaries reduced from $BEFORE to $AFTER."
