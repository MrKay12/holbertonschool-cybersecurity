#!/bin/bash
# 4-password_history.sh
# Configure pam_pwhistory so users cannot reuse their last 5 passwords.
#
# Note: on Debian/Ubuntu, running pam-auth-update later regenerates
# common-password and drops manual lines; re-run this script afterwards.

PAM_PASSWORD="/etc/pam.d/common-password"
OPASSWD="/etc/security/opasswd"
LOGIN_DEFS="/etc/login.defs"
REMEMBER=5
TEST_USER="pwhist_test"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run with sudo (sudo $0)" >&2
    exit 1
fi

echo "=== Password History Configuration ==="
echo
echo "Configuring pam_pwhistory..."
# Back up the PAM file before touching it (task 2's .backup stays intact)
cp /etc/pam.d/common-password /etc/pam.d/common-password.bak || exit 1
echo "  Backup: /etc/pam.d/common-password.bak"
echo

# ---- 1. History file -------------------------------------------------------
echo "Creating password history file..."
if [ -e /etc/security/opasswd ]; then
    echo "  /etc/security/opasswd: Already exists"
else
    touch /etc/security/opasswd
    echo "  /etc/security/opasswd: Created"
fi
# Holds old password hashes: root-only
chown root:root /etc/security/opasswd
chmod 600 /etc/security/opasswd
echo

# ---- 2. PAM stack ----------------------------------------------------------
# Order: pam_pwquality (quality) -> pam_pwhistory (reuse) -> pam_unix (store).
# Inserting right before pam_unix keeps its [success=1] jump correct.
echo "Updating $PAM_PASSWORD..."
if grep -qE '^[[:space:]]*password.*pam_pwhistory\.so' "$PAM_PASSWORD"; then
    # Already there: make sure it remembers the right number
    sed -i -E "/^[[:space:]]*password.*pam_pwhistory\.so/{
        s/remember=[0-9]+/remember=$REMEMBER/
        /remember=/!s/pam_pwhistory\.so/pam_pwhistory.so remember=$REMEMBER/
    }" "$PAM_PASSWORD"
    echo "  pam_pwhistory.so remember=$REMEMBER: Updated"
else
    sed -i -E "0,/^[[:space:]]*password.*pam_unix\.so/s//password\trequired\t\t\tpam_pwhistory.so remember=5 use_authtok\n&/" \
        /etc/pam.d/common-password
    echo "  pam_pwhistory.so remember=5: Added"
fi
# use_authtok: check the new password pam_pwquality already collected
sed -i -E '/^[[:space:]]*password.*pam_pwhistory\.so/{/use_authtok/!s/$/ use_authtok/}' \
    /etc/pam.d/common-password
# pam_unix must reuse the password already validated above it
sed -i -E '/^[[:space:]]*password.*pam_unix\.so/{/use_authtok/!s/pam_unix\.so/pam_unix.so use_authtok/}' \
    "$PAM_PASSWORD"
# Verify the final line with grep
pwh_line=$(grep -E 'pam_pwhistory.so' /etc/pam.d/common-password | grep -v '^[[:space:]]*#')
if ! echo "$pwh_line" | grep -q 'remember=5' || ! echo "$pwh_line" | grep -q 'use_authtok'; then
    echo "  Error: pam_pwhistory not configured (restore /etc/pam.d/common-password.bak)" >&2
    exit 1
fi
echo

# ---- 3. Report -------------------------------------------------------------
# Hash algorithm: pam_unix option first, else ENCRYPT_METHOD in login.defs
hash=$(grep -E '^[[:space:]]*password.*pam_unix\.so' "$PAM_PASSWORD" \
       | grep -oE '\b(yescrypt|gost_yescrypt|sha512|sha256|blowfish|md5|bigcrypt)\b' | head -1)
[ -z "$hash" ] && hash=$(awk '$1 == "ENCRYPT_METHOD" {print tolower($2)}' "$LOGIN_DEFS" 2>/dev/null)
echo "Configuration:"
echo "  Passwords remembered: $REMEMBER"
echo "  Hash algorithm: ${hash:-unknown}"
echo

# ---- 4. Test ---------------------------------------------------------------
# Throwaway user: P1 -> P2 with the real passwd (P1 goes into opasswd),
# then P2 -> P1 must be refused. Runs as the user so PAM is enforced.
echo "Testing..."
if id "$TEST_USER" >/dev/null 2>&1; then
    echo "  Error: user '$TEST_USER' already exists; skipping test" >&2
    exit 1
fi
cleanup() {
    userdel -r "$TEST_USER" >/dev/null 2>&1
    sed -i "/^$TEST_USER:/d" "$OPASSWD"     # drop its history entries
}
trap cleanup EXIT

rnd() { head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 10; }
P1="Hist!$(rnd)#7aQ"
P2="Cycle@$(rnd)%4zW"

change_pw() {   # $1 = old, $2 = new; exit 0 if PAM accepted the change
    printf '%s\n%s\n%s\n' "$1" "$2" "$2" \
        | timeout 15 su -s /bin/sh "$TEST_USER" -c passwd >/dev/null 2>&1
}

useradd -m -s /bin/bash "$TEST_USER" || exit 1
echo "$TEST_USER:$P1" | chpasswd
chage -m 0 "$TEST_USER"    # allow immediate changes

if ! change_pw "$P1" "$P2"; then
    echo "  Error: setup change P1 -> P2 failed; cannot test reuse" >&2
    exit 1
fi
if change_pw "$P2" "$P1"; then
    echo "  Previous password reuse: ALLOWED ✗"
    echo
    echo "Password history enforcement: NOT EFFECTIVE"
    exit 1
fi
echo "  Previous password reuse: BLOCKED ✓"
echo

echo "Password history enforcement: ACTIVE"
echo "Users cannot reuse their last $REMEMBER passwords."
