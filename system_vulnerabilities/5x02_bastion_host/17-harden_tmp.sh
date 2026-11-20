#!/bin/bash
# 17-harden_tmp.sh
# Mount /tmp with noexec,nosuid,nodev and make it persistent in /etc/fstab.

FSTAB="/etc/fstab"
LINE="tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run as root (sudo $0)" >&2
    exit 1
fi

echo "=== Hardening /tmp ==="
echo
echo "Current /tmp mount:"
CUR=$(mount | grep ' on /tmp ')
if [ -n "$CUR" ]; then
    echo "  $CUR"
else
    echo "  $(findmnt -n -o SOURCE,FSTYPE,OPTIONS -T /tmp | awk '{print $1" on /tmp (part of /) type "$2" ("$3")"}')"
fi

echo
echo "Applying hardening options..."
echo
echo "Method: Bind mount with options"
echo "Adding to $FSTAB:"
cp "$FSTAB" "$FSTAB.bak.$(date +%Y%m%d%H%M%S)"
if grep -qE '^[^#]*[[:space:]]/tmp[[:space:]]' "$FSTAB"; then
    # Replace the existing /tmp entry
    sed -i -E "s|^[^#]*[[:space:]]/tmp[[:space:]].*|$LINE|" "$FSTAB"
else
    echo "$LINE" >> "$FSTAB"
fi
echo "  $LINE"

echo
echo "Remounting /tmp..."
if mountpoint -q /tmp; then
    mount -o remount,noexec,nosuid,nodev /tmp
else
    mount -t tmpfs -o defaults,noexec,nosuid,nodev tmpfs /tmp
fi
chmod 1777 /tmp
systemctl daemon-reload 2>/dev/null

echo
echo "Verification:"
OPTS=$(findmnt -n -o OPTIONS /tmp)
echo "  /tmp mount options: $OPTS"

echo
echo "Testing restrictions:"
OK=1
TEST="/tmp/.exec_test_$$"
printf '#!/bin/sh\necho executed\n' > "$TEST"
chmod +x "$TEST"
if "$TEST" >/dev/null 2>&1; then
    echo "  Execute test: ALLOWED ✗"
    OK=0
else
    echo "  Execute test: BLOCKED (Permission denied) ✓"
fi
rm -f "$TEST"

if echo "$OPTS" | grep -qw nosuid; then
    echo "  SUID test: BLOCKED (nosuid active) ✓"
else
    echo "  SUID test: ALLOWED (nosuid missing) ✗"
    OK=0
fi

echo
if [ "$OK" -eq 1 ]; then
    echo "/tmp hardened successfully."
else
    echo "/tmp hardening FAILED."
    exit 1
fi
