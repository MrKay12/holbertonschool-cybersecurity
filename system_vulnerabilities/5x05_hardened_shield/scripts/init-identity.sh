#!/bin/bash
# =============================================================================
# init-identity.sh - NovaTech Hardened Shield: identity & access controls (5x03)
# =============================================================================
# Controls
#   1. Password policy (PAM) pam_pwquality (12 chars, 4 classes, difok 3,
#                            no username, enforce_for_root), pam_pwhistory
#                            (last 5), aging (max 90 / min 1 / warn 14,
#                            inactive 30), yescrypt hashing, no empty password
#   2. Account lockout       pam_faillock: 5 failures in 15 min -> locked
#                            15 min (root included); fail2ban jail for sshd
#   3. SSH hardening         key-only, no root, AllowGroups sshusers, modern
#                            crypto, no forwarding, MaxAuthTries 3, idle
#                            timeout, banner; optional TOTP (publickey +
#                            keyboard-interactive); no host key in the image;
#                            only valid ed25519/ecdsa/RSA>=3072 admin keys
#   4. Root lockdown         password locked, single UID 0, no SSH login,
#                            su restricted to an empty group, /root 0700,
#                            idle shell timeout (TMOUT)
#
# Modes
#   --build     apply every static control (Dockerfile)
#   --runtime   at container start (default): SSH host keys, admin key from
#               env/secret, optional MFA, then verify the critical controls;
#               writes the sshd options to /run/hardened-shield/sshd.args
#   --check     audit only, change nothing; non-compliance = exit 1
#
# Idempotent: a second run changes nothing and reports only [OK].
#
# Exit codes
#   0  compliant
#   1  a control failed or is non-compliant (the container must not start
#      an SSH service that is weaker than the policy: fail closed)
#   2  usage error / not run as root
#
# Runtime environment
#   SSH_ADMIN_USER          SSH login                     (default sysadmin)
#   SSH_ADMIN_PUBKEY        public key(s), one per line
#   SSH_ADMIN_PUBKEY_FILE   file with public key(s)       (default /run/secrets/ssh_admin_pubkey)
#   MFA_ENABLED             true = publickey + TOTP       (default false)
#   SSH_ADMIN_TOTP_FILE     google-authenticator file     (default /run/secrets/ssh_admin_totp)
#   SSH_HOSTKEY_DIR         persistent host keys          (default /var/lib/ssh-hostkeys)
# =============================================================================
set -uo pipefail

MODE="--runtime"
ADMIN="${SSH_ADMIN_USER:-sysadmin}"
SSH_GROUP="sshusers"
SU_GROUP="sugroup"
SSHD_CONFIG="/etc/ssh/sshd_config"
STATE_DIR="/run/hardened-shield"
AUTHKEYS_DIR="/run/ssh/authorized_keys"
MFA_DIR="/run/ssh-mfa"

# ---- policy ------------------------------------------------------------------
PWQUALITY="minlen=12 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 difok=3 usercheck=1 maxrepeat=3"
PWQUALITY_FLAGS="enforce_for_root"
PWHISTORY_REMEMBER=5
FAILLOCK="deny=5 fail_interval=900 unlock_time=900 root_unlock_time=900 dir=/var/run/faillock"
FAILLOCK_FLAGS="audit even_deny_root"
LOGIN_DEFS="PASS_MAX_DAYS=90 PASS_MIN_DAYS=1 PASS_WARN_AGE=14 UMASK=027 ENCRYPT_METHOD=YESCRYPT LOGIN_RETRIES=3 LOGIN_TIMEOUT=60"
INACTIVE_DAYS=30
SHELL_TMOUT=900

# sshd: KEY|VALUE (enforced in $SSHD_CONFIG, first occurrence wins in sshd)
SSHD_SETTINGS="
PermitRootLogin|no
PubkeyAuthentication|yes
AuthenticationMethods|publickey
PasswordAuthentication|no
PermitEmptyPasswords|no
KbdInteractiveAuthentication|yes
HostbasedAuthentication|no
IgnoreRhosts|yes
UsePAM|yes
AllowGroups|$SSH_GROUP
AuthorizedKeysFile|$AUTHKEYS_DIR/%u
StrictModes|yes
MaxAuthTries|3
MaxSessions|2
MaxStartups|10:30:60
LoginGraceTime|30
PermitUserEnvironment|no
ClientAliveInterval|300
ClientAliveCountMax|2
TCPKeepAlive|no
X11Forwarding|no
AllowTcpForwarding|no
AllowAgentForwarding|no
AllowStreamLocalForwarding|no
PermitTunnel|no
GatewayPorts|no
Compression|no
UseDNS|no
Banner|/etc/issue.net
LogLevel|VERBOSE
KexAlgorithms|curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers|chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs|hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
HostKeyAlgorithms|ssh-ed25519,rsa-sha2-512,rsa-sha2-256
"

PAM_FAILLOCK_PROFILE='Name: Enforce failed login attempt counter (pam_faillock)
Default: no
Priority: 0
Auth-Type: Primary
Auth:
	[default=die]	pam_faillock.so authfail
	sufficient	pam_faillock.so authsucc'

PAM_FAILLOCK_NOTIFY_PROFILE='Name: Check locked accounts before authentication (pam_faillock preauth)
Default: no
Priority: 1024
Auth-Type: Primary
Auth:
	requisite	pam_faillock.so preauth'

# ---- output / helpers --------------------------------------------------------
OKS=0; FIXES=0; WARNINGS=0; ERRORS=0

log()   { printf '%s [init-identity] %-5s %s\n' "$(date -u +%FT%TZ)" "$1" "$2"; }
ok()    { log OK "$1";    OKS=$((OKS + 1)); }
fix()   { log FIX "$1";   FIXES=$((FIXES + 1)); }
warn()  { log WARN "$1";  WARNINGS=$((WARNINGS + 1)); }
err()   { log ERROR "$1"; ERRORS=$((ERRORS + 1)); }
head_() { log INFO "--- $1 ---"; }
checking() { [ "$MODE" = "--check" ]; }

# remediate "description" command args...   (finding in --check, fix otherwise)
remediate() {
    local what="$1"; shift
    if checking; then
        err "non-compliant: $what"
        return 1
    fi
    if "$@" >/dev/null 2>&1; then
        fix "$what"
    else
        err "failed: $what"
        return 1
    fi
}

# require "description" test-command...      (verification only)
require() {
    local what="$1"; shift
    if "$@" >/dev/null 2>&1; then ok "$what"; else err "non-compliant: $what"; fi
}

# active_value FILE KEY SEP  -> value of the first non-comment KEY line
active_value() {
    awk -v k="$2" -v sep="$3" '
        /^[[:space:]]*#/ {next}
        {
            line = $0; sub(/^[[:space:]]+/, "", line)
            if (sep == "=") { n = index(line, "="); if (!n) next
                key = substr(line, 1, n - 1); val = substr(line, n + 1) }
            else { key = line; sub(/[[:space:]].*/, "", key)
                val = substr(line, length(key) + 1) }
            gsub(/[[:space:]]+$/, "", key); gsub(/^[[:space:]]+|[[:space:]]+$/, "", val)
            if (tolower(key) == tolower(k)) { print val; exit }
        }' "$1" 2>/dev/null
}

# set_kv FILE KEY VALUE SEP   SEP "=" -> "key = value", " " -> "Key value"
set_kv() {
    local file="$1" key="$2" want="$3" sep="$4" have line
    have=$(active_value "$file" "$key" "$sep")
    if [ "$have" = "$want" ]; then
        ok "$(basename "$file"): $key $want"
        return 0
    fi
    if [ "$sep" = "=" ]; then line="$key = $want"; else line="$key $want"; fi
    if [ -n "$have" ]; then
        # Replace every active occurrence (sshd uses the first one).
        remediate "$(basename "$file"): $key $have -> $want" sed -i -E \
            "s#^[[:space:]]*${key}([[:space:]]*=[[:space:]]*|[[:space:]]+).*#${line}#I" "$file"
    elif [ "$sep" = " " ] && grep -qiE '^[[:space:]]*Match[[:space:]]' "$file"; then
        # sshd: a line appended after a Match block would only apply to it.
        remediate "$(basename "$file"): add $key $want (before first Match)" bash -c '
            awk -v l="$2" "!d && tolower(\$1) == \"match\" {print l; d=1} {print}" "$1" > "$1.tmp" &&
            cat "$1.tmp" > "$1" && rm -f "$1.tmp"' _ "$file" "$line"
    else
        remediate "$(basename "$file"): add $key $want" \
            bash -c 'printf "%s\n" "$2" >> "$1"' _ "$file" "$line"
    fi
}

# set_flag FILE FLAG   (bare keyword such as "enforce_for_root")
set_flag() {
    if grep -qE "^[[:space:]]*$2[[:space:]]*$" "$1" 2>/dev/null; then
        ok "$(basename "$1"): $2"
    else
        remediate "$(basename "$1"): add $2" bash -c 'printf "%s\n" "$2" >> "$1"' _ "$1" "$2"
    fi
}

# write_file PATH MODE CONTENT  (only when the content differs)
write_file() {
    if [ -f "$1" ] && [ "$(cat "$1")" = "$3" ]; then
        ok "$1 up to date"
    else
        remediate "write $1" bash -c 'printf "%s\n" "$2" > "$1" && chmod "$3" "$1"' _ "$1" "$3" "$2"
    fi
}

has_rule() { grep -vE '^[[:space:]]*#' "$2" 2>/dev/null | grep -qE "$1"; }

# =============================================================================
# 1. Password policy (PAM)
# =============================================================================
pam_password_policy() {
    head_ "password policy: pam_pwquality"
    local f=/etc/security/pwquality.conf kv
    [ -f "$f" ] || { checking && err "non-compliant: $f missing"; checking || touch "$f"; }
    for kv in $PWQUALITY; do set_kv "$f" "${kv%%=*}" "${kv#*=}" "="; done
    for kv in $PWQUALITY_FLAGS; do set_flag "$f" "$kv"; done

    if has_rule 'pam_pwquality\.so' /etc/pam.d/common-password; then
        ok "pam_pwquality active in common-password"
    else
        remediate "enable pam_pwquality (pam-auth-update)" pam-auth-update --enable pwquality
    fi

    head_ "password policy: pam_pwhistory"
    local rule="password\trequired\t\t\tpam_pwhistory.so remember=$PWHISTORY_REMEMBER enforce_for_root use_authtok"
    if has_rule "pam_pwhistory\.so.*remember=$PWHISTORY_REMEMBER" /etc/pam.d/common-password; then
        ok "pam_pwhistory remember=$PWHISTORY_REMEMBER"
    elif has_rule 'pam_pwhistory\.so' /etc/pam.d/common-password; then
        remediate "pam_pwhistory remember -> $PWHISTORY_REMEMBER" sed -i -E \
            "s/^([[:space:]]*password.*pam_pwhistory\.so).*/$rule/" /etc/pam.d/common-password
    else
        # Before pam_unix: pwquality -> pwhistory -> unix (use_authtok)
        remediate "add pam_pwhistory remember=$PWHISTORY_REMEMBER" sed -i -E \
            "0,/^[[:space:]]*password.*pam_unix\.so/s//$rule\n&/" /etc/pam.d/common-password
    fi

    head_ "password policy: aging and hashing (login.defs)"
    for kv in $LOGIN_DEFS; do set_kv /etc/login.defs "${kv%%=*}" "${kv#*=}" " "; done
    local inactive
    inactive=$(useradd -D | awk -F= '$1 == "INACTIVE" {print $2}')
    if [ "$inactive" = "$INACTIVE_DAYS" ]; then
        ok "useradd default INACTIVE=$INACTIVE_DAYS"
    else
        remediate "useradd default INACTIVE $inactive -> $INACTIVE_DAYS" useradd -D -f "$INACTIVE_DAYS"
    fi

    head_ "password policy: existing accounts"
    local user uid pass max
    while IFS=: read -r user _ uid _; do
        [ "$uid" -ge 1000 ] && [ "$uid" -lt 60000 ] || continue
        max=$(chage -l "$user" 2>/dev/null | awk -F': ' '/Maximum number/ {print $2}')
        if [ "$max" = "90" ]; then
            ok "$user aging max 90"
        else
            remediate "$user aging: max 90, min 1, warn 14, inactive $INACTIVE_DAYS" \
                chage -M 90 -m 1 -W 14 -I "$INACTIVE_DAYS" "$user"
        fi
    done < /etc/passwd
    local empty
    empty=$(awk -F: '$2 == "" {print $1}' /etc/shadow)
    if [ -z "$empty" ]; then
        ok "no account with an empty password"
    else
        for user in $empty; do remediate "lock empty-password account $user" passwd -l "$user"; done
    fi
}

# =============================================================================
# 2. Account lockout
# =============================================================================
account_lockout() {
    head_ "account lockout: pam_faillock"
    local f=/etc/security/faillock.conf kv
    [ -f "$f" ] || { checking && err "non-compliant: $f missing"; checking || touch "$f"; }
    for kv in $FAILLOCK; do set_kv "$f" "${kv%%=*}" "${kv#*=}" "="; done
    for kv in $FAILLOCK_FLAGS; do set_flag "$f" "$kv"; done

    write_file /usr/share/pam-configs/faillock 0644 "$PAM_FAILLOCK_PROFILE"
    write_file /usr/share/pam-configs/faillock_notify 0644 "$PAM_FAILLOCK_NOTIFY_PROFILE"
    if has_rule 'pam_faillock\.so preauth' /etc/pam.d/common-auth \
       && has_rule 'pam_faillock\.so authfail' /etc/pam.d/common-auth \
       && has_rule 'pam_faillock\.so authsucc' /etc/pam.d/common-auth; then
        ok "pam_faillock preauth/authfail/authsucc in common-auth"
    else
        remediate "enable pam_faillock (pam-auth-update)" \
            pam-auth-update --enable faillock faillock_notify
    fi
    if has_rule 'pam_faillock\.so' /etc/pam.d/common-account; then
        ok "pam_faillock in common-account"
    else
        remediate "add pam_faillock to common-account" bash -c \
            'printf "account\trequired\t\t\tpam_faillock.so\n" >> /etc/pam.d/common-account'
    fi

    head_ "account lockout: fail2ban (sshd jail)"
    if [ -f /etc/fail2ban/jail.local ] && grep -qE '^\[sshd\]' /etc/fail2ban/jail.local; then
        ok "fail2ban sshd jail configured (started when NET_ADMIN is granted)"
    else
        warn "fail2ban sshd jail not configured (/etc/fail2ban/jail.local)"
    fi
}

# =============================================================================
# 3. SSH hardening
# =============================================================================
ssh_config() {
    head_ "ssh: $SSHD_CONFIG"
    [ -f "$SSHD_CONFIG" ] || { err "$SSHD_CONFIG missing"; return; }
    local key val
    while IFS='|' read -r key val; do
        [ -n "$key" ] && set_kv "$SSHD_CONFIG" "$key" "$val" " "
    done <<< "$SSHD_SETTINGS"
    # Drop-ins could override the settings above.
    if grep -qE '^[[:space:]]*Include' "$SSHD_CONFIG"; then
        remediate "remove Include (no drop-in may override the policy)" \
            sed -i -E '/^[[:space:]]*Include/d' "$SSHD_CONFIG"
    else
        ok "no Include directive"
    fi
    if [ -n "$(ls -A /etc/ssh/sshd_config.d 2>/dev/null)" ]; then
        remediate "remove sshd_config.d drop-ins" bash -c 'rm -f /etc/ssh/sshd_config.d/*'
    fi
    if [ "$(stat -c '%U:%G %a' "$SSHD_CONFIG")" = "root:root 600" ]; then
        ok "$SSHD_CONFIG root:root 600"
    else
        remediate "$SSHD_CONFIG root:root 600" bash -c "chown root:root $SSHD_CONFIG && chmod 600 $SSHD_CONFIG"
    fi
}

ssh_moduli() {
    local weak
    [ -f /etc/ssh/moduli ] || return 0
    weak=$(awk '$1 !~ /^#/ && $5 < 3071' /etc/ssh/moduli | wc -l)
    if [ "$weak" -eq 0 ]; then
        ok "DH moduli >= 3072 bits only"
    else
        remediate "remove $weak DH moduli < 3072 bits" bash -c \
            "awk '\$1 ~ /^#/ || \$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.tmp && mv /etc/ssh/moduli.tmp /etc/ssh/moduli"
    fi
}

ssh_pam() {
    head_ "ssh: PAM stack (TOTP + faillock)"
    local f=/etc/pam.d/sshd
    # Passwords never reach sshd (PasswordAuthentication no); the auth phase
    # is only used by the optional TOTP step.
    if grep -q '^@include common-auth' "$f"; then
        remediate "sshd PAM: replace password auth with faillock + TOTP" sed -i \
            's|^@include common-auth|# init-identity: TOTP step (used only when MFA_ENABLED=true)\
auth\trequisite\tpam_faillock.so preauth\
auth\t[success=1 default=ignore]\tpam_google_authenticator.so secret=/run/ssh-mfa/${USER}.totp user=root\
auth\t[default=die]\tpam_faillock.so authfail\
auth\tsufficient\tpam_faillock.so authsucc\
auth\trequisite\tpam_deny.so|' "$f"
    elif has_rule 'pam_google_authenticator\.so' "$f"; then
        ok "sshd PAM: faillock + TOTP stack"
    else
        err "sshd PAM: unexpected auth stack in $f"
    fi
    # pam_loginuid needs CAP_AUDIT_CONTROL, not granted to a hardened
    # container: "required" would block every login.
    if has_rule '^session[[:space:]]+required[[:space:]]+pam_loginuid' "$f"; then
        remediate "sshd PAM: pam_loginuid optional (no CAP_AUDIT_CONTROL)" sed -i -E \
            's/^(session[[:space:]]+)required([[:space:]]+pam_loginuid\.so)/\1optional\2/' "$f"
    else
        ok "sshd PAM: pam_loginuid not required"
    fi
}

ssh_accounts() {
    head_ "ssh: login accounts"
    if getent group "$SSH_GROUP" >/dev/null; then
        ok "group $SSH_GROUP exists"
    else
        remediate "create group $SSH_GROUP" groupadd --system "$SSH_GROUP"
    fi
    if ! id "$ADMIN" >/dev/null 2>&1; then
        err "admin account $ADMIN missing (created by the Dockerfile)"
        return
    fi
    if id -nG "$ADMIN" | grep -qw "$SSH_GROUP"; then
        ok "$ADMIN in $SSH_GROUP"
    else
        remediate "add $ADMIN to $SSH_GROUP" usermod -aG "$SSH_GROUP" "$ADMIN"
    fi
    local members
    members=$(getent group "$SSH_GROUP" | cut -d: -f4 | tr ',' '\n' | grep -vx "$ADMIN" | xargs)
    if [ -z "$members" ]; then ok "$SSH_GROUP has no other member"; else warn "$SSH_GROUP also contains: $members"; fi
    # sysadmin authenticates by key only: no usable password hash.
    local hash
    hash=$(getent shadow "$ADMIN" | cut -d: -f2)
    if [ "$hash" = "*" ]; then
        ok "$ADMIN has no password (key-only)"
    else
        remediate "$ADMIN: remove password (key-only)" usermod -p '*' "$ADMIN"
    fi
    local appshell
    appshell=$(getent passwd appuser | cut -d: -f7)
    if [ "$appshell" = /usr/sbin/nologin ]; then
        ok "appuser has nologin shell"
    elif [ -n "$appshell" ]; then
        remediate "appuser nologin shell" usermod -s /usr/sbin/nologin appuser
    fi
}

ssh_validate() {
    head_ "ssh: configuration test"
    local tmp
    tmp=$(mktemp -d) || { err "mktemp failed"; return; }
    ssh-keygen -q -t ed25519 -N '' -f "$tmp/k" >/dev/null 2>&1
    mkdir -p /run/sshd 2>/dev/null
    if sshd -t -f "$SSHD_CONFIG" -h "$tmp/k" 2>"$tmp/err"; then
        ok "sshd -t: configuration valid"
    else
        err "sshd -t: $(head -1 "$tmp/err")"
    fi
    rm -rf "$tmp"
    # A host key baked into the image would be shared by every container.
    local baked
    baked=$(ls /etc/ssh/ssh_host_*_key 2>/dev/null | xargs)
    if [ -z "$baked" ]; then
        ok "no SSH host key in the image"
    else
        remediate "remove baked host keys: $baked" bash -c 'rm -f /etc/ssh/ssh_host_*'
    fi
}

# =============================================================================
# 4. Root account lockdown
# =============================================================================
root_lockdown() {
    head_ "root lockdown"
    if [ "$(passwd -S root 2>/dev/null | awk '{print $2}')" = "L" ]; then
        ok "root password locked"
    else
        remediate "lock root password" passwd -l root
    fi
    local uid0
    uid0=$(awk -F: '$3 == 0 {print $1}' /etc/passwd | xargs)
    if [ "$uid0" = "root" ]; then ok "only root has UID 0"; else err "UID 0 accounts: $uid0"; fi
    if [ "$(active_value "$SSHD_CONFIG" PermitRootLogin " ")" = "no" ]; then
        ok "sshd PermitRootLogin no"
    else
        err "sshd PermitRootLogin is not 'no'"
    fi
    # su: only members of an empty group (CIS 5.6). With SUID bits stripped
    # su cannot elevate anyway; this keeps the policy if su is restored.
    if getent group "$SU_GROUP" >/dev/null; then
        ok "group $SU_GROUP exists"
    else
        remediate "create empty group $SU_GROUP" groupadd --system "$SU_GROUP"
    fi
    local sumembers
    sumembers=$(getent group "$SU_GROUP" | cut -d: -f4)
    [ -z "$sumembers" ] && ok "$SU_GROUP is empty" || warn "$SU_GROUP has members: $sumembers"
    if has_rule "pam_wheel\.so.*group=$SU_GROUP" /etc/pam.d/su; then
        ok "su restricted to $SU_GROUP (pam_wheel)"
    else
        # Right after pam_rootok: root itself is not affected.
        remediate "restrict su to $SU_GROUP (pam_wheel)" sed -i -E \
            "/^[[:space:]]*auth[[:space:]]+sufficient[[:space:]]+pam_rootok\.so/a auth       required   pam_wheel.so use_uid group=$SU_GROUP" /etc/pam.d/su
        has_rule "pam_wheel\.so.*group=$SU_GROUP" /etc/pam.d/su || checking \
            || err "pam_rootok line not found in /etc/pam.d/su"
    fi
    if [ "$(stat -c '%a' /root)" = "700" ]; then ok "/root 700"; else remediate "/root 700" chmod 700 /root; fi
    write_file /etc/profile.d/99-tmout.sh 0644 \
"# init-identity: idle interactive shells closed after $SHELL_TMOUT s
TMOUT=$SHELL_TMOUT
readonly TMOUT
export TMOUT"
}

# =============================================================================
# Runtime: host keys, admin key, MFA
# =============================================================================
runtime_hostkeys() {
    head_ "runtime: SSH host keys"
    KEYDIR="${SSH_HOSTKEY_DIR:-/var/lib/ssh-hostkeys}"
    if ! install -d -m 0700 -o root -g root "$KEYDIR" 2>/dev/null || [ ! -w "$KEYDIR" ]; then
        warn "$KEYDIR not writable: ephemeral host keys in /run (mount a volume to keep them)"
        KEYDIR=/run/ssh-hostkeys
        install -d -m 0700 -o root -g root "$KEYDIR" || { err "cannot create $KEYDIR"; return; }
    fi
    if [ -s "$KEYDIR/ssh_host_ed25519_key" ]; then
        ok "ed25519 host key present"
    else
        ssh-keygen -q -t ed25519 -N '' -C '' -f "$KEYDIR/ssh_host_ed25519_key" \
            && fix "generated ed25519 host key" || err "ed25519 host key generation failed"
    fi
    if [ -s "$KEYDIR/ssh_host_rsa_key" ]; then
        ok "rsa host key present"
    else
        ssh-keygen -q -t rsa -b 4096 -N '' -C '' -f "$KEYDIR/ssh_host_rsa_key" \
            && fix "generated rsa-4096 host key" || err "rsa host key generation failed"
    fi
    chmod 0600 "$KEYDIR"/ssh_host_*_key 2>/dev/null
    chmod 0644 "$KEYDIR"/ssh_host_*_key.pub 2>/dev/null
    log INFO "host key fingerprint: $(ssh-keygen -lf "$KEYDIR/ssh_host_ed25519_key.pub" 2>/dev/null | awk '{print $2}')"
    SSHD_ARGS+=("-h" "$KEYDIR/ssh_host_ed25519_key" "-h" "$KEYDIR/ssh_host_rsa_key")
}

runtime_authkeys() {
    head_ "runtime: admin authorized keys"
    local src="" raw="" line info bits type valid=0
    local file="${SSH_ADMIN_PUBKEY_FILE:-/run/secrets/ssh_admin_pubkey}"
    if [ -r "$file" ]; then raw=$(cat "$file"); src="$file"; fi
    if [ -n "${SSH_ADMIN_PUBKEY:-}" ]; then
        raw="$raw"$'\n'"$SSH_ADMIN_PUBKEY"; src="${src:+$src + }SSH_ADMIN_PUBKEY"
    fi
    install -d -m 0755 -o root -g root /run/ssh "$AUTHKEYS_DIR" || { err "cannot create $AUTHKEYS_DIR"; return; }
    local out="$AUTHKEYS_DIR/$ADMIN" tmp
    tmp=$(mktemp)
    while IFS= read -r line; do
        line="${line%$'\r'}"
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
        # Not fatal: the web service still starts; SSH simply admits nobody.
        warn "no admin key: SSH logins impossible (set SSH_ADMIN_PUBKEY or /run/secrets/ssh_admin_pubkey)"
    else
        ok "$valid authorized key(s) for $ADMIN from $src"
    fi
}

runtime_mfa() {
    head_ "runtime: MFA"
    install -d -m 0700 -o root -g root "$MFA_DIR" || { err "cannot create $MFA_DIR"; return; }
    local secret="${SSH_ADMIN_TOTP_FILE:-/run/secrets/ssh_admin_totp}"
    if [ "${MFA_ENABLED:-false}" != true ]; then
        log INFO "MFA disabled (MFA_ENABLED=true for publickey + TOTP)"
        return
    fi
    # Fail closed: never fall back to one factor when MFA was requested.
    if [ ! -r "$secret" ]; then
        err "MFA_ENABLED=true but $secret is missing"
        return
    fi
    install -m 0600 -o root -g root "$secret" "$MFA_DIR/$ADMIN.totp"
    SSHD_ARGS+=("-o" "AuthenticationMethods=publickey,keyboard-interactive")
    ok "MFA enabled for $ADMIN: publickey + TOTP"
}

runtime_verify() {
    head_ "runtime: critical controls"
    require "sshd PermitRootLogin no"        test "$(active_value "$SSHD_CONFIG" PermitRootLogin " ")" = no
    require "sshd PasswordAuthentication no" test "$(active_value "$SSHD_CONFIG" PasswordAuthentication " ")" = no
    require "sshd AllowGroups $SSH_GROUP"    test "$(active_value "$SSHD_CONFIG" AllowGroups " ")" = "$SSH_GROUP"
    require "root password locked"           test "$(passwd -S root 2>/dev/null | awk '{print $2}')" = L
    require "only root has UID 0"            test "$(awk -F: '$3 == 0' /etc/passwd | wc -l)" = 1
    require "pam_faillock active"            has_rule 'pam_faillock\.so preauth' /etc/pam.d/common-auth
    require "pam_pwquality active"           has_rule 'pam_pwquality\.so' /etc/pam.d/common-password
    install -d -m 0755 -o root -g root /var/run/faillock 2>/dev/null
}

# =============================================================================
usage() {
    awk 'NR == 1 {next} /^#/ {sub(/^# ?/, ""); print; next} {exit}' "$0"
    exit 0
}

case "${1:-}" in
    ""|--runtime) MODE="--runtime" ;;
    --build)      MODE="--build" ;;
    --check)      MODE="--check" ;;
    -h|--help)    usage ;;
    *)            echo "Usage: $0 [--build|--runtime|--check]" >&2; exit 2 ;;
esac

if [ "$(id -u)" -ne 0 ]; then
    echo "init-identity.sh: must run as root" >&2
    exit 2
fi
umask 027

log INFO "=== identity & access controls ($MODE) ==="
case "$MODE" in
    --build|--check)
        pam_password_policy
        account_lockout
        ssh_accounts
        ssh_config
        ssh_moduli
        ssh_pam
        root_lockdown
        ssh_validate
        ;;
    --runtime)
        SSHD_ARGS=()
        runtime_verify
        runtime_hostkeys
        runtime_authkeys
        runtime_mfa
        if [ "$ERRORS" -eq 0 ]; then
            install -d -m 0700 -o root -g root "$STATE_DIR"
            printf '%s\n' "${SSHD_ARGS[@]}" > "$STATE_DIR/sshd.args"
            chmod 0600 "$STATE_DIR/sshd.args"
            log INFO "sshd options written to $STATE_DIR/sshd.args"
        fi
        ;;
esac

log INFO "summary: ok=$OKS fixed=$FIXES warnings=$WARNINGS errors=$ERRORS"
[ "$ERRORS" -eq 0 ] || exit 1
exit 0
