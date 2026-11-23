#!/bin/bash
# 22-identity_audit.sh
# Final identity security audit: reads the live configuration (PAM, login.defs,
# faillock, fail2ban, effective sshd settings, /etc/shadow) and counts the
# controls that pass. Read-only: changes nothing.
#
# Human accounts = UID in UID_MIN..UID_MAX with a real login shell; service
# accounts (nologin/false) are excluded from the user checks.
#
# "Users with weak passwords" counts what can be proven from the hashes:
# empty passwords, and passwords flagged as compromised (expired with
# passwd -e / chage -d 0) that have not been changed yet.
#
# "Users without TOTP" is informational when MFA is mandatory (those users
# simply cannot log in over SSH); with nullok it becomes a counted check.

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run with sudo (sudo $0): /etc/shadow and sshd -T need root" >&2
    exit 1
fi

passed=0
total=0
check() {   # check <label> <PASS text> <FAIL text> <condition result 0/1>
    total=$((total + 1))
    if [ "$4" -eq 0 ]; then
        echo "  $1: $2"
        passed=$((passed + 1))
    else
        echo "  $1: $3"
    fi
}
ok() { "$@" >/dev/null 2>&1; echo $?; }     # run a test, print 0 (true) / 1

active() { grep -vE '^[[:space:]]*(#|$)' "$1" 2>/dev/null; }
conf_val() {   # conf_val <file> <key>: "key = value" or "key value"
    awk -v k="$2" '{sub(/#.*/, "")} {gsub(/=/, " ")} $1 == k {v = $2} END {print v}' "$1" 2>/dev/null
}
pam_opt() {    # pam_opt <file> <module> <option>: value of option=N on the module line
    active "$1" | grep "$2" | grep -oE "$3=[0-9]+" | head -1 | cut -d= -f2
}
def() { awk -v k="$1" '$1 == k {v = $2} END {print v}' /etc/login.defs; }
sshd_opt() { sshd -T 2>/dev/null | awk -v k="$1" '$1 == k {print $2; exit}'; }

UID_MIN=$(def UID_MIN); UID_MIN=${UID_MIN:-1000}
UID_MAX=$(def UID_MAX); UID_MAX=${UID_MAX:-60000}
humans=$(awk -F: -v lo="$UID_MIN" -v hi="$UID_MAX" \
    '$3 >= lo && $3 <= hi && $7 !~ /(nologin|false)$/ && $7 != "" {print $1}' /etc/passwd)
today=$(( $(date +%s) / 86400 ))

echo "=== Identity Security Audit ==="
echo

# ---- Password policy -------------------------------------------------------
echo "Password Policy:"
check "Complexity enforcement" "ACTIVE" "NOT ACTIVE (2-password_complexity.sh)" \
    "$(ok grep -qE '^[[:space:]]*password.*pam_pwquality\.so' /etc/pam.d/common-password)"

minlen=$(pam_opt /etc/pam.d/common-password pam_pwquality minlen)
[ -z "$minlen" ] && minlen=$(conf_val /etc/security/pwquality.conf minlen)
check "Minimum length 12" "CONFIGURED" "NOT CONFIGURED (minlen=${minlen:-default 8})" \
    "$(ok test "${minlen:-0}" -ge 12)"

remember=$(pam_opt /etc/pam.d/common-password pam_pwhistory remember)
[ -z "$remember" ] && remember=$(conf_val /etc/security/pwhistory.conf remember)
has_hist=$(ok grep -qE '^[[:space:]]*password.*pam_pwhistory\.so' /etc/pam.d/common-password)
[ "$has_hist" -eq 0 ] && [ "${remember:-0}" -ge 5 ]; hist_ok=$?
check "History (5 passwords)" "CONFIGURED" "NOT CONFIGURED (remember=${remember:-none})" "$hist_ok"

# Aging: default for new accounts AND applied to every human account
max_def=$(def PASS_MAX_DAYS)
not_aged=0
for u in $humans; do
    m=$(awk -F: -v u="$u" '$1 == u {print $5}' /etc/shadow)
    { [ -z "$m" ] || [ "$m" -gt 90 ]; } && not_aged=$((not_aged + 1))
done
[ "${max_def:-99999}" -le 90 ] && [ "$not_aged" -eq 0 ]; aging_ok=$?
check "Aging (90 days max)" "CONFIGURED" \
    "NOT CONFIGURED (PASS_MAX_DAYS=${max_def:-unset}, $not_aged user(s) not aged)" "$aging_ok"
echo

# ---- Account protection ----------------------------------------------------
echo "Account Protection:"
active /etc/pam.d/common-auth | grep -q 'pam_faillock.*preauth' \
    && active /etc/pam.d/common-auth | grep -q 'pam_faillock.*authfail' \
    && active /etc/pam.d/common-account | grep -q 'pam_faillock'
faillock_on=$?
check "pam_faillock" "ACTIVE" "NOT ACTIVE (8-configure_faillock.sh)" "$faillock_on"

# A threshold only protects anything if pam_faillock is in the stack
deny=$(pam_opt /etc/pam.d/common-auth pam_faillock deny)
[ -z "$deny" ] && deny=$(conf_val /etc/security/faillock.conf deny)
deny=${deny:-3}
[ "$faillock_on" -eq 0 ] && [ "$deny" -ge 1 ] && [ "$deny" -le 5 ]
lockout_ok=$?     # capture before building the message (it runs commands)
[ "$faillock_on" -eq 0 ] && fl_state="on" || fl_state="off"
check "Lockout after 5 attempts" "CONFIGURED" "NOT CONFIGURED (deny=$deny, faillock $fl_state)" "$lockout_ok"

systemctl is-active --quiet fail2ban && fail2ban-client status sshd >/dev/null 2>&1
check "fail2ban for SSH" "ACTIVE" "NOT ACTIVE (10-configure_fail2ban.sh)" "$?"
echo

# ---- SSH security (effective sshd settings) --------------------------------
echo "SSH Security:"
# sshd -T prints the effective settings, in lowercase (hence grep -i)
sshd -T 2>/dev/null | grep -qi "^PasswordAuthentication no"
check "Password authentication" "DISABLED" "ENABLED (14-disable_password_auth.sh)" "$?"
check "Public key authentication" "ENABLED" "DISABLED" \
    "$(ok test "$(sshd_opt pubkeyauthentication)" = yes)"

# MFA = sshd requires key then keyboard-interactive, and PAM asks for TOTP
sshd -T 2>/dev/null | grep -qi "^AuthenticationMethods publickey,keyboard-interactive" \
    && sshd -T 2>/dev/null | grep -qi "^KbdInteractiveAuthentication yes" \
    && active /etc/pam.d/sshd | grep -q 'pam_google_authenticator\.so'
check "MFA required" "ENABLED" "NOT ENABLED (18-ssh_mfa.sh)" "$?"
echo

# ---- User compliance -------------------------------------------------------
echo "User Compliance:"
weak=0; expired=0; no_totp=0
for u in $humans; do
    IFS=: read -r _ hash last _ max _ <<< "$(grep "^$u:" /etc/shadow)"
    # empty password, or flagged compromised and not changed yet
    { [ -z "$hash" ] || [ "$last" = "0" ]; } && weak=$((weak + 1))
    # password older than its maximum age
    [ -n "$last" ] && [ "$last" != "0" ] && [ -n "$max" ] && [ "$max" -lt 99999 ] \
        && [ $((last + max)) -lt "$today" ] && expired=$((expired + 1))
    home=$(getent passwd "$u" | cut -d: -f6)
    [ -s "$home/.google_authenticator" ] || no_totp=$((no_totp + 1))
done
check "Users with weak passwords" "0" "$weak (6-force_password_change.sh pending / empty)" \
    "$(ok test "$weak" -eq 0)"
if active /etc/pam.d/sshd | grep -q 'pam_google_authenticator\.so.*nullok'; then
    # nullok: these users log in with a key only -> real gap
    check "Users without TOTP" "0" "$no_totp (nullok lets them skip MFA)" \
        "$(ok test "$no_totp" -eq 0)"
else
    echo "  Users without TOTP: $no_totp (service accounts excluded)"
fi
check "Accounts past password age" "0" "$expired" "$(ok test "$expired" -eq 0)"
echo

# ---- Summary ---------------------------------------------------------------
pct=$(( passed * 100 / total ))
if [ "$passed" -eq "$total" ]; then level="STRONG"
elif [ "$pct" -ge 75 ]; then level="MODERATE"
else level="WEAK"; fi

echo "Summary:"
echo "  Identity controls: $passed/$total PASSED"
echo "  Compliance level: $level"
echo

if [ "$level" = "STRONG" ]; then
    echo "System ready for production deployment."
else
    echo "System NOT ready for production: fix the controls above."
    exit 1
fi
