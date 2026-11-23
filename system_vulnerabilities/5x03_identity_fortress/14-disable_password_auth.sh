#!/bin/bash
# 14-disable_password_auth.sh
# Disable SSH password authentication, keep key-based access.
#
# Usage: sudo ./14-disable_password_auth.sh [--force]
#   --force  skip the interactive confirmation when the key login cannot be
#            tested automatically (the key presence check is never skipped)
#
# Safety:
# - Refuses to run unless the admin (the user who ran sudo) has a valid key
#   in ~/.ssh/authorized_keys.
# - Tries a real key-only login to localhost; if that cannot be tested
#   (passphrase key, no agent under sudo), asks for confirmation.
# - Settings go into sshd_config AND a sshd_config.d/00- drop-in: sshd uses
#   the FIRST value it reads, and cloud images (Multipass) ship
#   sshd_config.d/50-cloud-init.conf with "PasswordAuthentication yes".
# - sshd -t failure => backups restored, SSH not reloaded.
# - Already-open SSH sessions survive the reload.
#
# Emergency access if locked out: Multipass `multipass shell <vm>`, or the
# VM console; restore /etc/ssh/sshd_config.backup.<date> and remove
# /etc/ssh/sshd_config.d/00-identity-fortress.conf.

DROPIN="/etc/ssh/sshd_config.d/00-identity-fortress.conf"
BACKUP="/etc/ssh/sshd_config.backup.$(date +%Y%m%d)"
FORCE=0
[ "$1" = "--force" ] && FORCE=1

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run with sudo (sudo $0)" >&2
    exit 1
fi

ADMIN="${SUDO_USER:-root}"
ADMIN_HOME=$(getent passwd "$ADMIN" | cut -d: -f6)
AUTH_KEYS="$ADMIN_HOME/.ssh/authorized_keys"

echo "=== Disable SSH Password Authentication ==="
echo

# Effective sshd value of an option (lowercase), from sshd -T
effective() { sshd -T 2>/dev/null | awk -v k="$1" '$1 == k {print $2; exit}'; }

# ---- 1. Pre-flight ---------------------------------------------------------
echo "Pre-flight checks:"
echo "  Current user has SSH key: CHECKING..."
valid_keys=0
if [ -f "$AUTH_KEYS" ]; then
    # count keys ssh-keygen can parse (comments/blank lines ignored)
    valid_keys=$(grep -vE '^[[:space:]]*(#|$)' "$AUTH_KEYS" | while read -r line; do
        printf '%s\n' "$line" | ssh-keygen -lf /dev/stdin >/dev/null 2>&1 && echo ok
    done | wc -l)
fi
if [ "$valid_keys" -eq 0 ]; then
    echo "  $ADMIN has no valid key in $AUTH_KEYS: ABORTING ✗" >&2
    echo "  Deploy a key first (12-generate_ssh_key.sh, 13-deploy_ssh_key.sh)." >&2
    exit 1
fi
echo "  $ADMIN: $valid_keys key(s) in authorized_keys ✓"

# Real key-only login as the admin, no password fallback possible
if sudo -u "$ADMIN" ssh -o BatchMode=yes -o PreferredAuthentications=publickey \
        -o PasswordAuthentication=no -o StrictHostKeyChecking=accept-new \
        -o ConnectTimeout=5 "$ADMIN@localhost" true >/dev/null 2>&1; then
    echo "  Key-based auth working: YES ✓"
else
    echo "  Key-based auth working: NOT TESTABLE from this script"
    echo "  (normal for a passphrase-protected key without ssh-agent)"
    if [ "$FORCE" -ne 1 ]; then
        if [ ! -t 0 ]; then
            echo "Aborting: no terminal to confirm. Test a key login, then re-run with --force." >&2
            exit 1
        fi
        echo "  In ANOTHER terminal, check: ssh -o PreferredAuthentications=publickey $ADMIN@<this host>"
        read -r -p "  Did that key login work? Type YES to continue: " answer
        [ "$answer" = "YES" ] || { echo "Aborted, nothing changed."; exit 1; }
    fi
fi
echo

echo "WARNING: This will disable password authentication."
echo "Ensure you have working key-based access!"
echo

# ---- 2. Backup -------------------------------------------------------------
echo "Backing up sshd_config..."
cp -p /etc/ssh/sshd_config "$BACKUP" || exit 1
echo "  $BACKUP"
dropin_existed=0
[ -f "$DROPIN" ] && { dropin_existed=1; cp -p "$DROPIN" "$DROPIN.bak"; }
echo

rollback() {
    cp -p "$BACKUP" /etc/ssh/sshd_config
    if [ "$dropin_existed" -eq 1 ]; then cp -p "$DROPIN.bak" "$DROPIN"; else rm -f "$DROPIN"; fi
}

# ---- 3. Modify -------------------------------------------------------------
old_pw=$(effective passwordauthentication)
old_kbd=$(effective kbdinteractiveauthentication)
old_pam=$(effective usepam)

echo "Modifying /etc/ssh/sshd_config..."
# Set "Key value" on active and commented-out lines; add it at the top
# (before any Match block) if the keyword is absent.
set_opt() {
    if grep -qE "^[#[:space:]]*$1[[:space:]]" /etc/ssh/sshd_config; then
        sed -i -E "s/^[#[:space:]]*$1[[:space:]].*/$1 $2/" /etc/ssh/sshd_config
    else
        sed -i "1i $1 $2" /etc/ssh/sshd_config
    fi
}
set_opt PasswordAuthentication no
set_opt ChallengeResponseAuthentication no
set_opt KbdInteractiveAuthentication no
set_opt PubkeyAuthentication yes

# Drop-in read before 50-cloud-init.conf and the rest of sshd_config
mkdir -p /etc/ssh/sshd_config.d
cat > "$DROPIN" <<'EOF'
# Managed by 14-disable_password_auth.sh: key-only SSH
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
EOF
chmod 644 "$DROPIN"
grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config \
    || echo "  Note: sshd_config has no Include for sshd_config.d (drop-in unused)"

echo "  PasswordAuthentication: ${old_pw:-yes} → no"
echo "  ChallengeResponseAuthentication: ${old_kbd:-yes} → no"
echo "  UsePAM: ${old_pam:-yes} (preserving for account checks)"
echo

# ---- 4. Validate -----------------------------------------------------------
echo "Validating configuration..."
if sshd -t; then
    echo "  sshd -t: Configuration OK"
else
    echo "  sshd -t: FAILED, restoring backup (SSH not reloaded)" >&2
    rollback
    exit 1
fi
echo

# ---- 5. Reload -------------------------------------------------------------
# Debian/Ubuntu name the unit ssh.service (sshd.service is an alias)
echo "Reloading SSH..."
if systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null; then
    echo "  sshd.service: Reloaded"
else
    echo "  Error: SSH reload failed (systemctl status ssh)" >&2
    exit 1
fi
echo

# ---- 6. Verify (effective config) -----------------------------------------
pw=$(effective passwordauthentication)
pk=$(effective pubkeyauthentication)
echo "Verification:"
[ "$pw" = "no" ] && echo "  Password auth: DISABLED" || echo "  Password auth: STILL ENABLED ($pw)"
[ "$pk" = "yes" ] && echo "  Pubkey auth: ENABLED" || echo "  Pubkey auth: DISABLED ($pk)"
echo

if [ "$pw" = "no" ] && [ "$pk" = "yes" ]; then
    echo "SSH now requires key-based authentication."
else
    echo "Error: effective sshd settings are not as expected (sshd -T)" >&2
    exit 1
fi
