#!/bin/bash
# 18-ssh_mfa.sh
# Require BOTH an SSH key AND a TOTP code for SSH logins:
#   sshd:  AuthenticationMethods publickey,keyboard-interactive
#   PAM:   the keyboard-interactive step runs /etc/pam.d/sshd, which now asks
#          only for the TOTP code (pam_google_authenticator). "@include
#          common-auth" is disabled there, otherwise the Unix password would
#          be asked again (password auth was removed in task 14).
#
# Usage: sudo ./18-ssh_mfa.sh [--nullok]
#   --nullok  users without ~/.google_authenticator log in with their key
#             only (gradual rollout). Without it they are locked out of SSH.
#
# Safety:
# - Aborts if the admin running sudo has not enrolled (17-setup_user_totp.sh).
# - Lists users with SSH keys but no TOTP secret before changing anything.
# - sshd -t or PAM check failure => both files restored, SSH not reloaded.
# - Already-open SSH sessions survive the reload: test a NEW login before
#   closing yours. Emergency access: `multipass shell <vm>` / VM console,
#   then restore the .backup files and `systemctl reload ssh`.

DROPIN="/etc/ssh/sshd_config.d/00-identity-fortress.conf"
NULLOK=""
[ "$1" = "--nullok" ] && NULLOK=" nullok"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run with sudo (sudo $0)" >&2
    exit 1
fi

echo "=== SSH Multi-Factor Authentication ==="
echo

# ---- Pre-flight ------------------------------------------------------------
module=$(dpkg -L libpam-google-authenticator 2>/dev/null | grep '/pam_google_authenticator\.so$' | head -1)
if [ -z "$module" ]; then
    echo "Error: pam_google_authenticator not installed (run 16-install_google_auth.sh)" >&2
    exit 1
fi

ADMIN="${SUDO_USER:-root}"
ADMIN_HOME=$(getent passwd "$ADMIN" | cut -d: -f6)
if [ ! -s "$ADMIN_HOME/.google_authenticator" ]; then
    echo "Error: $ADMIN has no TOTP secret ($ADMIN_HOME/.google_authenticator)." >&2
    echo "Run ./17-setup_user_totp.sh as $ADMIN first, or you will be locked out." >&2
    exit 1
fi

# Users with SSH keys but no TOTP secret
unenrolled=""
while IFS=: read -r user _ uid _ _ home shell; do
    [ "$uid" -ge 1000 ] && [ "$uid" -lt 65534 ] || [ "$user" = "root" ] || continue
    case "$shell" in */nologin|*/false|"") continue ;; esac
    [ -s "$home/.ssh/authorized_keys" ] || continue
    [ -s "$home/.google_authenticator" ] || unenrolled="$unenrolled $user"
done < /etc/passwd
if [ -n "$unenrolled" ]; then
    if [ -n "$NULLOK" ]; then
        echo "Note: not enrolled yet (key only until they enroll, --nullok):$unenrolled"
    else
        echo "WARNING: these users have SSH keys but no TOTP secret and will be"
        echo "locked out of SSH until they enroll (or re-run with --nullok):$unenrolled"
    fi
    echo
fi

# ---- 1. Backups ------------------------------------------------------------
echo "Backing up configurations..."
cp /etc/pam.d/sshd /etc/pam.d/sshd.backup || exit 1
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup || exit 1
echo "  /etc/pam.d/sshd.backup"
echo "  /etc/ssh/sshd_config.backup"
dropin_existed=0
[ -f "$DROPIN" ] && { dropin_existed=1; cp "$DROPIN" "$DROPIN.backup"; }
echo

rollback() {
    cp /etc/pam.d/sshd.backup /etc/pam.d/sshd
    cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
    if [ "$dropin_existed" -eq 1 ]; then cp "$DROPIN.backup" "$DROPIN"; else rm -f "$DROPIN"; fi
}

# ---- 2. PAM ----------------------------------------------------------------
echo "Configuring /etc/pam.d/sshd..."
GA_LINE="auth required pam_google_authenticator.so$NULLOK"
if grep -qE '^[[:space:]]*auth[[:space:]].*pam_google_authenticator\.so' /etc/pam.d/sshd; then
    sed -i -E "s|^[[:space:]]*auth[[:space:]].*pam_google_authenticator\.so.*|$GA_LINE|" /etc/pam.d/sshd
    echo "  Already present: $GA_LINE"
elif grep -qE '^[[:space:]]*@include[[:space:]]+common-auth' /etc/pam.d/sshd; then
    # TOTP replaces the Unix password step of the SSH auth stack
    sed -i -E "s|^[[:space:]]*@include[[:space:]]+common-auth.*|$GA_LINE\n#@include common-auth  # disabled by 18-ssh_mfa.sh (key + TOTP, no password)|" \
        /etc/pam.d/sshd
    echo "  Adding: $GA_LINE"
else
    sed -i "0,/^[^#[:space:]]/s//$GA_LINE\n&/" /etc/pam.d/sshd
    echo "  Adding: $GA_LINE"
fi
# never leave common-auth active next to the TOTP line
sed -i -E 's|^[[:space:]]*@include[[:space:]]+common-auth.*|#@include common-auth  # disabled by 18-ssh_mfa.sh (key + TOTP, no password)|' \
    /etc/pam.d/sshd
echo

# ---- 3. sshd ---------------------------------------------------------------
old_kbd=$(sshd -T 2>/dev/null | awk '$1 == "kbdinteractiveauthentication" {print $2}')

echo "Configuring /etc/ssh/sshd_config..."
set_opt() {   # set "Key value" on active/commented lines, else add at the top
    if grep -qE "^[#[:space:]]*$1[[:space:]]" "$3"; then
        sed -i -E "s/^[#[:space:]]*$1[[:space:]].*/$1 $2/" "$3"
    else
        sed -i "1i $1 $2" "$3"
    fi
}
for f in /etc/ssh/sshd_config "$DROPIN"; do
    [ -f "$f" ] || continue
    set_opt ChallengeResponseAuthentication yes "$f"
    set_opt KbdInteractiveAuthentication yes "$f"
    set_opt UsePAM yes "$f"
    set_opt PasswordAuthentication no "$f"
    set_opt PubkeyAuthentication yes "$f"
    set_opt AuthenticationMethods publickey,keyboard-interactive "$f"
done
echo "  ChallengeResponseAuthentication: ${old_kbd:-no} → yes"
echo "  AuthenticationMethods: publickey,keyboard-interactive"
echo

# ---- 4. Validate -----------------------------------------------------------
echo "Validating configuration..."
if sshd -t; then
    echo "  sshd -t: OK"
else
    echo "  sshd -t: FAILED, restoring backups (SSH not reloaded)" >&2
    rollback
    exit 1
fi

# PAM has no syntax checker: check every active line by hand
pam_ok=1
secdir=$(dirname "$module")
while read -r type control mod rest; do
    case "$type" in
        ""|\#*) continue ;;
        @include) [ -f "/etc/pam.d/$control" ] || { pam_ok=0; echo "  missing include: $control" >&2; } ;;
        auth|account|password|session|-auth|-account|-password|-session)
            # "[...]" controls may contain spaces: take the first *.so word
            m=$(echo "$control $mod $rest" | grep -oE '[^[:space:]]+\.so' | head -1)
            if [ -z "$m" ] || { [ "${m#/}" = "$m" ] && [ ! -f "$secdir/$m" ] && [ "${type#-}" = "$type" ]; }; then
                pam_ok=0; echo "  bad line: $type $control $mod" >&2
            fi ;;
        *) pam_ok=0; echo "  unknown type: $type" >&2 ;;
    esac
done < /etc/pam.d/sshd
if [ "$pam_ok" -eq 1 ] && grep -q '^auth required pam_google_authenticator.so' /etc/pam.d/sshd; then
    echo "  PAM syntax: OK"
else
    echo "  PAM syntax: FAILED, restoring backups (SSH not reloaded)" >&2
    rollback
    exit 1
fi
echo

# ---- 5. Reload -------------------------------------------------------------
echo "Reloading SSH..."
if systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null; then
    echo "  sshd.service: Reloaded"
else
    echo "  Error: SSH reload failed (systemctl status ssh)" >&2
    exit 1
fi
echo

# ---- 6. Verify (effective config) -----------------------------------------
methods=$(sshd -T 2>/dev/null | awk '$1 == "authenticationmethods" {print $2}')
kbd=$(sshd -T 2>/dev/null | awk '$1 == "kbdinteractiveauthentication" {print $2}')
if [ "$methods" != "publickey,keyboard-interactive" ] || [ "$kbd" != "yes" ]; then
    echo "Error: effective sshd settings not applied (sshd -T: $methods, kbd=$kbd)" >&2
    exit 1
fi

echo "SSH MFA Configuration:"
echo "  First factor: SSH Public Key"
echo "  Second factor: TOTP Code (Google Authenticator)"
echo

echo "Users must now provide BOTH key AND TOTP code to log in."
echo "Keep this session open and test a NEW login in another terminal."
