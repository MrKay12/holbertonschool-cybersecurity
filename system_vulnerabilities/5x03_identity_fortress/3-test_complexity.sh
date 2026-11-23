#!/bin/bash
# 3-test_complexity.sh
# Verify that the pam_pwquality policy really rejects weak passwords.
#
# Uses pwscore (libpwquality-tools): it runs the same libpwquality checks
# and reads the same /etc/security/pwquality.conf as pam_pwquality does at
# passwd time, without changing any account's password.
#
# Usage: ./3-test_complexity.sh [-v]
#   -v  also show libpwquality's own message for each test

TEST_USER="auditor"
VERBOSE=0
[ "$1" = "-v" ] && VERBOSE=1

if ! command -v pwscore >/dev/null; then
    echo "Error: pwscore not found (run 2-password_complexity.sh first," \
         "or: sudo apt-get install libpwquality-tools)" >&2
    exit 1
fi

# password | description | expected (REJECTED/ACCEPTED) | reason tested
TESTS=(
    "password|common word|REJECTED|Dictionary word"
    "Password123|no special char|REJECTED|Missing special character"
    "Ab1!|too short|REJECTED|Minimum length not met"
    "auditor2024|contains username|REJECTED|Contains username"
    "Str0ng!P@ssw0rd#2024|valid|ACCEPTED|Meets all requirements"
)

echo "=== Password Complexity Testing ==="
echo
echo "Testing password policy enforcement..."
echo

n=0
failed=0
for t in "${TESTS[@]}"; do
    IFS='|' read -r pw desc expected reason <<< "$t"
    n=$((n + 1))

    # pwscore exits 0 and prints a score when the password passes
    msg=$(printf '%s\n' "$pw" | pwscore "$TEST_USER" 2>&1)
    if [ $? -eq 0 ]; then result="ACCEPTED"; else result="REJECTED"; fi

    echo "Test $n: \"$pw\" ($desc)"
    if [ "$result" = "$expected" ]; then
        echo "  Result: $result ✓"
        echo "  Reason: $reason"
    else
        echo "  Result: $result ✗ (expected $expected)"
        echo "  Reason: policy does not enforce: $reason"
        failed=$((failed + 1))
    fi
    if [ "$VERBOSE" -eq 1 ]; then
        echo "  pwquality: $(echo "$msg" | grep -v '^Password quality check failed:' \
                             | sed 's/^[[:space:]]*//' | head -1)"
    fi
    echo
done

if [ "$failed" -eq 0 ]; then
    echo "All complexity tests: PASSED"
    echo "Password policy is enforced correctly."
else
    echo "Complexity tests: $failed of $n FAILED"
    echo "Password policy is NOT enforced correctly (run 2-password_complexity.sh)."
    exit 1
fi
