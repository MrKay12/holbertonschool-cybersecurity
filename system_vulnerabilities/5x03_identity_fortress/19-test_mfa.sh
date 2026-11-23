#!/bin/bash
# 19-test_mfa.sh
# Verify that SSH requires BOTH a key and a TOTP code.
#
# Usage: ./19-test_mfa.sh [host]     (default host: localhost)
#   Run as the enrolled user (no sudo needed). The SSH tests are real login
#   attempts that never reach a shell:
#   1. key only, BatchMode (cannot answer the TOTP prompt): the server must
#      accept the key with "partial success", i.e. still want the 2nd factor
#   2. no key: the server must refuse before any TOTP prompt
#   If test 1 cannot use your key (passphrase without ssh-agent), it is
#   reported INCONCLUSIVE: run `ssh-add` first.

HOST="${1:-localhost}"
USER_NAME="${SUDO_USER:-$(whoami)}"
USER_HOME=$(getent passwd "$USER_NAME" | cut -d: -f6)
passed=0
failed=0
inconclusive=0

ok()   { echo "  $1 ✓"; passed=$((passed + 1)); }
bad()  { echo "  $1 ✗"; failed=$((failed + 1)); }
skip() { echo "  $1"; inconclusive=$((inconclusive + 1)); }

# Run ssh as the tested user (matters when the script runs under sudo)
as_user() {
    if [ "$(id -u)" -eq 0 ] && [ "$USER_NAME" != "root" ]; then
        sudo -u "$USER_NAME" "$@"
    else
        "$@"
    fi
}
SSH_OPTS="-o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new"

# Effective sshd option (lowercase key): sshd -T as root, else the config
# files in sshd's order (sshd_config.d/*.conf first), first value wins.
sshd_opt() {
    if [ "$(id -u)" -eq 0 ]; then
        sshd -T 2>/dev/null | awk -v k="$1" '$1 == k {print $2; exit}'
    else
        cat /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null \
            | awk -v k="$1" 'tolower($1) == "match" {exit}
                             tolower($1) == k {print $2; exit}'
    fi
}

echo "=== MFA Testing ==="
echo
echo "Testing authentication requirements..."
echo

# ---- Test 1: key only ------------------------------------------------------
echo "Test 1: SSH with key only (no TOTP)"
echo "  Expected: Prompt for verification code"
# The key from 12-generate_ssh_key.sh, else the user's other default key
KEY="$USER_HOME/.ssh/id_ed25519"
for k in id_ed25519 id_ecdsa id_rsa; do
    [ -f "$USER_HOME/.ssh/$k" ] && { KEY="$USER_HOME/.ssh/$k"; break; }
done
out=$(as_user ssh -i "$KEY" -v $SSH_OPTS -o PreferredAuthentications=publickey,keyboard-interactive \
      "$USER_NAME@$HOST" true 2>&1)
if echo "$out" | grep -qi 'partial success'; then
    ok "Result: CORRECT"
elif echo "$out" | grep -q 'Authenticated to'; then
    bad "Result: WRONG (logged in with the key alone)"
elif echo "$out" | grep -qi 'Server accepts key'; then
    # key accepted but no second-factor step was asked for
    bad "Result: WRONG (key accepted, no second-factor step)"
elif echo "$out" | grep -qi 'Offering public key'; then
    skip "Result: INCONCLUSIVE (key not in $USER_NAME's authorized_keys on $HOST)"
else
    skip "Result: INCONCLUSIVE (key not usable non-interactively: run ssh-add)"
fi
echo

# ---- Test 2: no key --------------------------------------------------------
echo "Test 2: SSH with TOTP only (no key)"
echo "  Expected: Connection refused"
out=$(as_user ssh $SSH_OPTS -o PubkeyAuthentication=no \
      -o PreferredAuthentications=keyboard-interactive,password \
      "$USER_NAME@$HOST" true 2>&1)
if echo "$out" | grep -q 'Permission denied (publickey)'; then
    ok "Result: CORRECT"
elif echo "$out" | grep -qiE 'Connection refused|timed out|Could not resolve'; then
    skip "Result: INCONCLUSIVE (cannot reach sshd on $HOST)"
else
    bad "Result: WRONG ($(echo "$out" | tail -1))"
fi
echo

# ---- Test 3: PAM -----------------------------------------------------------
echo "Test 3: PAM configuration check"
if grep -qE '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_google_authenticator\.so' /etc/pam.d/sshd; then
    ok "pam_google_authenticator.so: Present in /etc/pam.d/sshd"
else
    bad "pam_google_authenticator.so: MISSING from /etc/pam.d/sshd"
fi
if grep -qE '^[[:space:]]*@include[[:space:]]+common-auth' /etc/pam.d/sshd; then
    bad "@include common-auth: still active (Unix password asked too)"
fi
echo

# ---- Test 4: sshd ----------------------------------------------------------
echo "Test 4: SSH configuration check"
methods=$(sshd_opt authenticationmethods)
kbd=$(sshd_opt kbdinteractiveauthentication)
[ -z "$kbd" ] && kbd=$(sshd_opt challengeresponseauthentication)
kbd=$(echo "$kbd" | tr 'A-Z' 'a-z')
if [ "AuthenticationMethods $methods" = "AuthenticationMethods publickey,keyboard-interactive" ]; then
    ok "AuthenticationMethods: $methods"
else
    bad "AuthenticationMethods: ${methods:-any} (expected publickey,keyboard-interactive)"
fi
if [ "$kbd" = "yes" ]; then
    ok "ChallengeResponseAuthentication: yes"
else
    bad "ChallengeResponseAuthentication: ${kbd:-unset} (expected yes)"
fi
echo

# ---- Test 5: user secret ---------------------------------------------------
echo "Test 5: User TOTP configuration"
GA_FILE="$USER_HOME/.google_authenticator"
if [ -s "$GA_FILE" ]; then
    ok "~/.google_authenticator: Exists"
    mode=$(stat -c %a "$GA_FILE")
    # owner-only (400 or 600): pam_google_authenticator rejects anything else
    if [ "$mode" = "600" ] || [ "$mode" = "400" ]; then
        ok "Permissions ($mode): Correct"
    else
        bad "Permissions ($mode): WRONG (must be 600 or 400)"
    fi
else
    bad "~/.google_authenticator: MISSING (run 17-setup_user_totp.sh)"
fi
echo

if [ "$failed" -eq 0 ] && [ "$inconclusive" -eq 0 ]; then
    echo "All MFA tests: PASSED"
    echo "Two-factor authentication is properly configured."
elif [ "$failed" -eq 0 ]; then
    echo "MFA tests: $passed passed, $inconclusive inconclusive"
    echo "Fix the inconclusive test(s) above and re-run."
    exit 2
else
    echo "MFA tests: $failed FAILED"
    echo "Two-factor authentication is NOT properly configured."
    exit 1
fi
