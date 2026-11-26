#!/bin/bash
# init-identity.sh - identity controls from 5x03 (identity fortress)
#
#   --build    PAM policy (pwquality, pwhistory, faillock), password aging,
#              account checks, sshd PAM stack for MFA, sshd config test,
#              no SSH host key left in the image
#   --runtime  at every start (default): SSH host keys, admin authorized key
#              from env/secret, optional TOTP MFA; writes the sshd options
#              to /run/hardened-shield/sshd.args for init-services.sh
#
# Runtime variables:
#   SSH_ADMIN_USER          login allowed over SSH        (default sysadmin)
#   SSH_ADMIN_PUBKEY        public key(s), one per line
#   SSH_ADMIN_PUBKEY_FILE   file holding public key(s)    (or /run/secrets/ssh_admin_pubkey)
#   MFA_ENABLED             true = publickey + TOTP       (default false)
#   SSH_ADMIN_TOTP_FILE     google-authenticator file     (default /run/secrets/ssh_admin_totp)
#   SSH_HOSTKEY_DIR         persistent host keys          (default /var/lib/ssh-hostkeys)
set -uo pipefail

MODE="${1:---runtime}"
ADMIN="${SSH_ADMIN_USER:-sysadmin}"
STATE_DIR="/run/hardened-shield"
AUTHKEYS_DIR="/run/ssh/authorized_keys"
MFA_DIR="/run/ssh-mfa"

log()  { printf '%s [init-identity] %-5s %s\n' "$(date -u +%FT%TZ)" "$1" "$2"; }
ok()   { log OK "$1"; }
fix()  { log FIX "$1"; }
warn() { log WARN "$1"; }
die()  { log ERROR "$1"; exit 1; }

[ "$(id -u)" -eq 0 ] || { echo "init-identity.sh: must run as root" >&2; exit 1; }

set_def() {   # login.defs KEY VALUE
    if grep -qE "^[#[:space:]]*$1[[:space:]]" /etc/login.defs; then
        sed -i -E "s|^[#[:space:]]*$1[[:space:]].*|$1\t$2|" /etc/login.defs
    else
        printf '%s\t%s\n' "$1" "$2" >> /etc/login.defs
    fi
}

# --------------------------------------------------------------------------
build_pam() {
    # Complexity (5x03 task 2): pam_pwquality profile ships enabled with
    # libpam-pwquality; policy lives in /etc/security/pwquality.conf.
    # Lockout (task 8): pam_faillock profiles in /usr/share/pam-configs.
    pam-auth-update --enable pwquality faillock faillock_notify >/dev/null \
        || die "pam-auth-update failed"
    grep -q 'pam_pwquality.so' /etc/pam.d/common-password || die "pam_pwquality not active"
    grep -q 'pam_faillock.so preauth' /etc/pam.d/common-auth || die "pam_faillock preauth not active"
    grep -q 'pam_faillock.so authfail' /etc/pam.d/common-auth || die "pam_faillock authfail not active"
    ok "pam_pwquality + pam_faillock enabled"

    if ! grep -q 'pam_faillock.so' /etc/pam.d/common-account; then
        printf 'account\trequired\t\t\tpam_faillock.so\n' >> /etc/pam.d/common-account
    fi
    ok "pam_faillock account phase enabled"

    # History (task 4): last 5 passwords, inserted before pam_unix
    if ! grep -q 'pam_pwhistory.so' /etc/pam.d/common-password; then
        sed -i -E '0,/^[[:space:]]*password.*pam_unix\.so/s//password\trequired\t\t\tpam_pwhistory.so remember=5 enforce_for_root use_authtok\n&/' \
            /etc/pam.d/common-password
    fi
    grep -q 'pam_pwhistory.so remember=5' /etc/pam.d/common-password || die "pam_pwhistory not active"
    ok "pam_pwhistory remember=5 enabled"
}

build_sshd_pam() {
    # sshd PAM stack. Passwords are never accepted by sshd (config), so the
    # auth phase is used only for the optional TOTP step (task 18):
    # faillock preauth -> TOTP -> faillock authfail/authsucc.
    local f=/etc/pam.d/sshd
    if grep -q '^@include common-auth' "$f"; then
        sed -i 's|^@include common-auth|# 5x05: password auth replaced by TOTP (only used when MFA_ENABLED=true)\
auth\trequisite\tpam_faillock.so preauth\
auth\t[success=1 default=ignore]\tpam_google_authenticator.so secret=/run/ssh-mfa/${USER}.totp user=root\
auth\t[default=die]\tpam_faillock.so authfail\
auth\tsufficient\tpam_faillock.so authsucc\
auth\trequisite\tpam_deny.so|' "$f"
        fix "sshd PAM: TOTP + faillock stack"
    fi
    # pam_loginuid needs CAP_AUDIT_CONTROL, which a hardened container does
    # not get: without this a "required" failure would block every login.
    sed -i -E 's/^(session[[:space:]]+)required([[:space:]]+pam_loginuid\.so)/\1optional\2/' "$f"
    ok "sshd PAM stack ready"
}

build_aging() {
    # Password aging (task 5) and inactive-account lock
    set_def PASS_MAX_DAYS 90
    set_def PASS_MIN_DAYS 1
    set_def PASS_WARN_AGE 14
    set_def UMASK 027
    set_def ENCRYPT_METHOD YESCRYPT
    useradd -D -f 30 >/dev/null
    local u
    for u in "$ADMIN"; do
        id "$u" >/dev/null 2>&1 && chage -M 90 -m 1 -W 14 -I 30 "$u"
    done
    ok "password aging: max 90, min 1, warn 14, inactive 30"
}

build_accounts() {
    local extra
    extra=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)
    [ -z "$extra" ] || die "UID 0 accounts besides root: $extra"
    extra=$(awk -F: '$2 == "" {print $1}' /etc/shadow)
    [ -z "$extra" ] || die "accounts with empty password: $extra"
    id appuser >/dev/null 2>&1 || die "appuser missing"
    [ "$(getent passwd appuser | cut -d: -f7)" = /usr/sbin/nologin ] || die "appuser must have nologin shell"
    id -nG "$ADMIN" 2>/dev/null | grep -qw sshusers || die "$ADMIN is not in sshusers"
    ok "accounts: single UID 0, no empty password, appuser nologin, $ADMIN in sshusers"
}

build_sshd() {
    # Strong DH moduli only (>= 3072 bits)
    if [ -f /etc/ssh/moduli ]; then
        awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.tmp \
            && mv /etc/ssh/moduli.tmp /etc/ssh/moduli
    fi
    # Validate the config with a throw-away key, then make sure no host key
    # is shipped in the image (a baked key is a shared secret).
    local tmp
    tmp=$(mktemp -d)
    ssh-keygen -q -t ed25519 -N '' -f "$tmp/k" >/dev/null
    mkdir -p /run/sshd
    sshd -t -f /etc/ssh/sshd_config -h "$tmp/k" || { rm -rf "$tmp"; die "sshd_config invalid"; }
    rm -rf "$tmp" /etc/ssh/ssh_host_* /etc/ssh/sshd_config.d/*
    ok "sshd_config valid, no host key in image"
}

# --------------------------------------------------------------------------
runtime_hostkeys() {
    KEYDIR="${SSH_HOSTKEY_DIR:-/var/lib/ssh-hostkeys}"
    if ! install -d -m 0700 -o root -g root "$KEYDIR" 2>/dev/null || [ ! -w "$KEYDIR" ]; then
        warn "$KEYDIR not writable: using ephemeral host keys in /run (mount a volume to keep them)"
        KEYDIR=/run/ssh-hostkeys
        install -d -m 0700 -o root -g root "$KEYDIR" || die "cannot create $KEYDIR"
    fi
    if [ ! -s "$KEYDIR/ssh_host_ed25519_key" ]; then
        ssh-keygen -q -t ed25519 -N '' -C '' -f "$KEYDIR/ssh_host_ed25519_key" || die "host key generation failed"
        fix "generated ed25519 host key"
    fi
    if [ ! -s "$KEYDIR/ssh_host_rsa_key" ]; then
        ssh-keygen -q -t rsa -b 4096 -N '' -C '' -f "$KEYDIR/ssh_host_rsa_key" || die "host key generation failed"
        fix "generated rsa-4096 host key"
    fi
    chmod 0600 "$KEYDIR"/ssh_host_*_key
    chmod 0644 "$KEYDIR"/ssh_host_*_key.pub
    ok "host key: $(ssh-keygen -lf "$KEYDIR/ssh_host_ed25519_key.pub" | awk '{print $2}')"
}

runtime_authkeys() {
    # Collect candidate keys; keep only valid ed25519 / ecdsa / rsa >= 3072
    local src="" raw="" line info bits type valid=0
    local file="${SSH_ADMIN_PUBKEY_FILE:-/run/secrets/ssh_admin_pubkey}"
    if [ -r "$file" ]; then raw=$(cat "$file"); src="$file"; fi
    if [ -n "${SSH_ADMIN_PUBKEY:-}" ]; then raw="$raw"$'\n'"$SSH_ADMIN_PUBKEY"; src="${src:+$src + }SSH_ADMIN_PUBKEY"; fi

    install -d -m 0755 -o root -g root /run/ssh "$AUTHKEYS_DIR"
    local out="$AUTHKEYS_DIR/$ADMIN" tmp
    tmp=$(mktemp)
    while IFS= read -r line; do
        line=$(echo "$line" | tr -d '\r')
        [[ -z "$line" || "$line" == \#* ]] && continue
        if ! info=$(printf '%s\n' "$line" | ssh-keygen -lf /dev/stdin 2>/dev/null); then
            warn "ignored invalid public key line"
            continue
        fi
        bits=$(awk '{print $1}' <<< "$info"); type=$(awk '{print $NF}' <<< "$info")
        case "$type" in
            "(ED25519)"|"(ECDSA)"|"(ED25519-SK)"|"(ECDSA-SK)") ;;
            "(RSA)") [ "$bits" -ge 3072 ] || { warn "ignored RSA key < 3072 bits"; continue; } ;;
            *) warn "ignored key type $type"; continue ;;
        esac
        printf '%s\n' "$line" >> "$tmp"
        valid=$((valid + 1))
    done <<< "$raw"

    install -m 0644 -o root -g root "$tmp" "$out"
    rm -f "$tmp"
    if [ "$valid" -eq 0 ]; then
        warn "no admin public key provided: SSH logins impossible (set SSH_ADMIN_PUBKEY or /run/secrets/ssh_admin_pubkey)"
    else
        ok "$valid authorized key(s) for $ADMIN from $src"
    fi
}

runtime_mfa() {
    install -d -m 0700 -o root -g root "$MFA_DIR"
    local secret="${SSH_ADMIN_TOTP_FILE:-/run/secrets/ssh_admin_totp}"
    if [ "${MFA_ENABLED:-false}" != true ]; then
        log INFO "MFA disabled (MFA_ENABLED=true for publickey + TOTP)"
        return
    fi
    # Fail closed: MFA requested but no seed -> do not start an SSH service
    # that would silently fall back to a single factor.
    [ -r "$secret" ] || die "MFA_ENABLED=true but $secret is missing"
    install -m 0600 -o root -g root "$secret" "$MFA_DIR/$ADMIN.totp"
    SSHD_ARGS+=("-o" "AuthenticationMethods=publickey,keyboard-interactive")
    ok "MFA enabled for $ADMIN: publickey + TOTP"
}

# --------------------------------------------------------------------------
case "$MODE" in
    --build)
        log INFO "=== build-time identity controls ==="
        build_pam
        build_sshd_pam
        build_aging
        build_accounts
        build_sshd
        ;;
    --runtime)
        log INFO "=== runtime identity setup ==="
        umask 027
        SSHD_ARGS=()
        runtime_hostkeys
        SSHD_ARGS+=("-h" "$KEYDIR/ssh_host_ed25519_key" "-h" "$KEYDIR/ssh_host_rsa_key")
        runtime_authkeys
        runtime_mfa
        install -d -m 0700 -o root -g root "$STATE_DIR"
        printf '%s\n' "${SSHD_ARGS[@]}" > "$STATE_DIR/sshd.args"
        chmod 0600 "$STATE_DIR/sshd.args"
        ;;
    *)
        echo "Usage: $0 [--build|--runtime]" >&2
        exit 2
        ;;
esac
exit 0
