#!/bin/bash
# 6-force_password_change.sh
# Force the given users (e.g. accounts whose weak passwords the pentest
# cracked) to change their password at next login.
#
# Usage: sudo ./6-force_password_change.sh user1 [user2 ...]

if [ $# -eq 0 ]; then
    echo "Usage: $0 user1 [user2 ...]" >&2
    exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run with sudo (sudo $0 $*)" >&2
    exit 1
fi

echo "=== Force Password Change ==="
echo
echo "Processing users with compromised passwords..."
echo

forced=0
failed=0
first=""
for user in "$@"; do
    echo "$user:"
    if ! id "$user" >/dev/null 2>&1; then
        echo "  ERROR: no such user, skipped"
        echo
        failed=$((failed + 1))
        continue
    fi

    # Expire the password: last change date = 0 (day zero).
    # passwd -e and chage -d 0 do the same; chage is the fallback.
    # (usernames cannot contain spaces, so $user needs no quoting)
    passwd -e $user >/dev/null 2>&1 || chage -d 0 $user

    # Verify in /etc/shadow: field 3 (last change) must be 0
    lastchg=$(awk -F: -v u="$user" '$1 == u {print $3}' /etc/shadow)
    if [ "$lastchg" = "0" ]; then
        echo "  Password expired: FORCED"
        echo "  Must change at next login: YES"
        forced=$((forced + 1))
        [ -z "$first" ] && first="$user"
    else
        echo "  Password expired: FAILED"
        echo "  Must change at next login: NO"
        failed=$((failed + 1))
    fi
    echo
done

if [ -n "$first" ]; then
    echo "Verification:"
    echo "  chage -l $first | grep \"Password expires\""
    chage -l "$first" | grep "Password expires" | sed -E 's/^/  /; s/[[:space:]]+:[[:space:]]*/: /'
    echo
fi

echo "$forced users must change password at next login."
if [ "$failed" -gt 0 ]; then
    echo "$failed user(s) could not be processed."
    exit 1
fi
