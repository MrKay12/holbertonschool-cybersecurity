#!/bin/bash
# 3-test_complexity.sh
# Verify that the pam_pwquality policy really rejects weak passwords.
#
# Each password is tried with the real passwd command, run as a throwaway
# user so it goes through the full PAM password stack (root would bypass
# pam_pwquality). The throwaway user is deleted on exit; no real account's
# password is ever touched.
#
# The test user is "audit", so "auditor2024" contains its username.
#
# Usage: sudo ./3-test_complexity.sh [-v]
#   -v  also show the message passwd/PAM printed for each test

TEST_USER="audit"
VERBOSE=0
[ "$1" = "-v" ] && VERBOSE=1

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run with sudo (sudo $0)" >&2
    exit 1
fi
if id "$TEST_USER" >/dev/null 2>&1; then
    echo "Error: user '$TEST_USER' already exists; refusing to touch it" >&2
    exit 1
fi

# Description / expected result / reason for each test password, in the
# same order as the passwords in the for loop below
DESCS=("common word" "no special char" "too short" "contains username" "valid")
EXPECTED=("REJECTED" "REJECTED" "REJECTED" "REJECTED" "ACCEPTED")
REASONS=("Dictionary word" "Missing special character" "Minimum length not met" \
         "Contains username" "Meets all requirements")

# ---- Throwaway test user ---------------------------------------------------
cleanup() { userdel -r "$TEST_USER" >/dev/null 2>&1; }
trap cleanup EXIT

# Random initial password (set by root, so not subject to the policy)
OLD_PW="Init!$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 12)9a"
useradd -m -s /bin/bash "$TEST_USER" || { echo "Error: cannot create $TEST_USER" >&2; exit 1; }
echo "$TEST_USER:$OLD_PW" | chpasswd
chage -m 0 "$TEST_USER"    # allow an immediate password change

# Try to change the password as the user: old, new, new on stdin.
# Exit 0 means PAM accepted the new password.
#
# The naive form is:   echo '$test_pass' | passwd auditor
# It is NOT used: single quotes send the literal text "$test_pass", root
# skips pam_pwquality (so nothing is ever rejected), and it would target
# the real auditor account. Running passwd as the test user fixes all three.
try_passwd() {
    printf '%s\n%s\n%s\n' "$OLD_PW" "$1" "$1" \
        | timeout 15 su -s /bin/sh "$TEST_USER" -c passwd 2>&1
}

echo '=== Password Complexity Testing ==='
echo
echo "Testing password policy enforcement..."
echo

i=0
failed=0
for test_pass in 'password' 'Password123' 'Ab1!' 'auditor2024' 'Str0ng!P@ssw0rd#2024'; do
    msg=$(try_passwd "$test_pass")
    if [ $? -eq 0 ]; then
        result="ACCEPTED"
        OLD_PW="$test_pass"     # the change went through
    else
        result="REJECTED"
    fi

    echo "Test $((i + 1)): \"$test_pass\" (${DESCS[$i]})"
    if [ "$result" = "${EXPECTED[$i]}" ]; then
        echo "  Result: $result ✓"
        echo "  Reason: ${REASONS[$i]}"
    else
        echo "  Result: $result ✗ (expected ${EXPECTED[$i]})"
        echo "  Reason: policy does not enforce: ${REASONS[$i]}"
        failed=$((failed + 1))
    fi
    if [ "$VERBOSE" -eq 1 ]; then
        echo "  passwd: $(echo "$msg" | grep -iE 'BAD PASSWORD|updated|error|fail' | head -1)"
    fi
    echo
    i=$((i + 1))
done

if [ "$failed" -eq 0 ]; then
    echo "All complexity tests: PASSED"
    echo "Password policy is enforced correctly."
else
    echo "Complexity tests: $failed of $i FAILED"
    echo "Password policy is NOT enforced correctly (run 2-password_complexity.sh)."
    exit 1
fi
