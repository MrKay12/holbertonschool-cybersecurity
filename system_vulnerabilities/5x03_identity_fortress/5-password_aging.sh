#!/bin/bash
# 5-password_aging.sh
# Password aging policy: max 90 days, min 1 day (no rapid cycling),
# warn 14 days before expiry. Sets the defaults for new accounts in
# /etc/login.defs and applies them to existing human accounts with chage.
#
# Service accounts (UID below UID_MIN, nobody, or a nologin/false shell)
# are skipped so they keep working.

MAX=90
MIN=1
WARN=14

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run with sudo (sudo $0)" >&2
    exit 1
fi

echo "=== Password Aging Configuration ==="
echo

# ---- 1. Defaults for new accounts ------------------------------------------
cp /etc/login.defs /etc/login.defs.bak || exit 1

# Current value of a login.defs key (empty if unset)
get_def() { awk -v k="$1" '$1 == k {v = $2} END {print v}' /etc/login.defs; }

# Set "KEY<TAB>value": replace the active line, else append
set_def() {
    local key="$1" val="$2" old
    old=$(get_def "$key")
    if grep -qE "^[[:space:]]*$key[[:space:]]" /etc/login.defs; then
        sed -i -E "s/^[[:space:]]*$key[[:space:]].*/$key\t$val/" /etc/login.defs
    else
        printf '%s\t%s\n' "$key" "$val" >> /etc/login.defs
    fi
    echo "  $key: ${old:-unset} → $val"
}

echo "Configuring /etc/login.defs..."
set_def PASS_MAX_DAYS "$MAX"
set_def PASS_MIN_DAYS "$MIN"
set_def PASS_WARN_AGE "$WARN"

# Verify
if [ "$(get_def PASS_MAX_DAYS)" != "$MAX" ] || [ "$(get_def PASS_MIN_DAYS)" != "$MIN" ] \
   || [ "$(get_def PASS_WARN_AGE)" != "$WARN" ]; then
    echo "  Error: login.defs not updated (restore /etc/login.defs.bak)" >&2
    exit 1
fi
echo
echo "Note: These settings apply to NEW accounts only."
echo "Existing accounts must be updated with chage."
echo

# ---- 2. Existing human accounts --------------------------------------------
uid_min=$(get_def UID_MIN); uid_min=${uid_min:-1000}
uid_max=$(get_def UID_MAX); uid_max=${uid_max:-60000}

echo "Applying to existing users..."
failed=0
while IFS=: read -r user _ uid _ _ _ shell; do
    # Human accounts only: regular UID range, real login shell
    [ "$uid" -ge "$uid_min" ] && [ "$uid" -le "$uid_max" ] || continue
    case "$shell" in */nologin|*/false|"") continue ;; esac

    if chage -M "$MAX" -m "$MIN" -W "$WARN" "$user"; then
        # Read back what chage actually stored
        read -r smax smin swarn <<< "$(awk -F: -v u="$user" '$1 == u {print $5, $4, $6}' /etc/shadow)"
        echo "  $user: Max=$smax, Min=$smin, Warn=$swarn"
        [ "$smax" = "$MAX" ] && [ "$smin" = "$MIN" ] && [ "$swarn" = "$WARN" ] || failed=1
    else
        echo "  $user: FAILED" >&2
        failed=1
    fi
done < /etc/passwd
echo "  [Skipping system accounts]"
echo

if [ "$failed" -eq 0 ]; then
    echo "Password aging: CONFIGURED"
else
    echo "Password aging: INCOMPLETE (see errors above)"
    exit 1
fi
