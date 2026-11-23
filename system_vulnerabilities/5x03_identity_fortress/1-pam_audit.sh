#!/bin/bash
# 1-pam_audit.sh
# Read-only audit of the current PAM / identity configuration.
# Documents the baseline (auth stack, password policy, lockout, aging, SSH)
# before any hardening so changes can be compared and rolled back.
#
# Usage: ./1-pam_audit.sh [--clear-stale-locks]
#   --clear-stale-locks  (root) remove leftover apt/dpkg lock files when no
#                        package manager is running, then verify. Off by
#                        default: a plain run changes nothing.

PAM_DIR="/etc/pam.d"
LOGIN_DEFS="/etc/login.defs"
SSHD_CONFIG="/etc/ssh/sshd_config"
WEAK=0

# Short description for security-relevant PAM modules.
# Plumbing modules (pam_permit, pam_cap, pam_gnome_keyring, ...) return
# nothing and are left out of the report.
describe() {
    local file="$1" mod="$2"
    case "$mod" in
        pam_unix.so)
            if [ "$file" = "common-password" ]; then echo "Password change handling"
            else echo "Standard password authentication"; fi ;;
        pam_deny.so)       [ "$file" = "common-auth" ] && echo "Fallback deny" ;;
        pam_faillock.so)   echo "Account lockout after failed attempts" ;;
        pam_tally2.so)     echo "Legacy failed-login counter" ;;
        pam_pwquality.so)  echo "Password complexity enforcement" ;;
        pam_cracklib.so)   echo "Password complexity (legacy)" ;;
        pam_pwhistory.so)  echo "Password history enforcement" ;;
        pam_sss.so)        echo "SSSD (directory) authentication" ;;
        pam_krb5.so)       echo "Kerberos authentication" ;;
        pam_ldap.so)       echo "LDAP authentication" ;;
        pam_google_authenticator.so|pam_oath.so|pam_u2f.so|pam_duo.so|pam_yubico.so)
                           echo "Multi-factor authentication" ;;
    esac
}

# Print "  module: description" for each security-relevant module of a file
report_modules() {
    local file="$1" name="$2" m d
    for m in $(modules "$file"); do
        d=$(describe "$name" "$m")
        [ -n "$d" ] && echo "  $m: $d"
    done
}

# Active (non-comment) lines of a PAM file
active() { grep -vE '^[[:space:]]*(#|$)' "$1" 2>/dev/null; }

# Unique module names in order of appearance
modules() { active "$1" | grep -oE 'pam_[a-zA-Z0-9_]+\.so' | awk '!seen[$0]++'; }

# ---- Pre-flight: package manager activity ----------------------------------
# dpkg runs pam-auth-update, which rewrites /etc/pam.d/common-*. Auditing
# while apt/dpkg is running could capture a half-written PAM stack.
# Messages go to stderr so the audit report on stdout is unchanged.
lock_files="/var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock"

pkg_busy() {
    # Running package manager processes
    pgrep -x 'apt|apt-get|aptitude|dpkg|unattended-upgr' >/dev/null && return 0
    # A process still holding one of the lock files
    command -v fuser >/dev/null && fuser $lock_files >/dev/null 2>&1 && return 0
    return 1
}

if pkg_busy; then
    echo "WARNING: apt/dpkg is running; PAM files may change during the audit" >&2
elif [ "$1" = "--clear-stale-locks" ]; then
    if [ "$(id -u)" -ne 0 ]; then
        echo "Error: --clear-stale-locks needs root (sudo $0 $1)" >&2
        exit 1
    fi
    # No apt/dpkg process is running, so any lock file left is stale
    for l in $lock_files; do
        [ -e "$l" ] && rm -f "$l" && echo "Removed stale lock: $l" >&2
    done
    # Verify: locks gone, nothing grabbed them, dpkg database consistent
    left=0
    for l in $lock_files; do [ -e "$l" ] && left=1; done
    if [ "$left" -eq 0 ] && ! pkg_busy && dpkg --audit >/dev/null 2>&1; then
        echo "Lock cleanup verified: no locks left, dpkg database consistent" >&2
    else
        echo "WARNING: lock cleanup could not be verified (run: dpkg --audit)" >&2
    fi
fi

echo "=== PAM Configuration Audit ==="
echo

# ---- common-auth -----------------------------------------------------------
f="$PAM_DIR/common-auth"
echo "$f:"
if [ -r "$f" ]; then
    report_modules "$f" common-auth
else
    echo "  NOT FOUND"
fi
echo

# ---- common-password -------------------------------------------------------
f="$PAM_DIR/common-password"
echo "$f:"
if [ -r "$f" ]; then
    # Complexity/history modules get their own lines below
    report_modules "$f" common-password \
        | grep -vE 'pam_(pwquality|cracklib|pwhistory)\.so'

    cx=$(active "$f" | grep -oE 'pam_(pwquality|cracklib)\.so' | head -1)
    if [ -n "$cx" ]; then
        echo "  Complexity enforcement: $cx"
    else
        echo "  Complexity enforcement: NONE"; WEAK=$((WEAK + 1))
    fi

    if active "$f" | grep -q 'pam_pwhistory\.so'; then
        echo "  History enforcement: pam_pwhistory.so"
    elif r=$(active "$f" | grep -oE 'remember=[0-9]+' | head -1) && [ -n "$r" ]; then
        echo "  History enforcement: pam_unix $r"
    else
        echo "  History enforcement: NONE"; WEAK=$((WEAK + 1))
    fi
else
    echo "  NOT FOUND"
fi
echo

# ---- sshd ------------------------------------------------------------------
f="$PAM_DIR/sshd"
echo "$f:"
if [ -r "$f" ]; then
    # Only the authentication include matters for this audit
    active "$f" | grep -E '^[[:space:]]*@include[[:space:]]+common-auth' \
        | awk '{print "  " $1 " " $2}'
    # MFA can live in sshd itself or in the included common-auth
    mfa=$({ active "$f"; active "$PAM_DIR/common-auth"; } \
          | grep -oE 'pam_(google_authenticator|oath|u2f|duo|yubico)\.so' | sort -u | tr '\n' ' ')
    if [ -n "$mfa" ]; then
        echo "  MFA modules: ${mfa% }"
    else
        echo "  MFA modules: NONE"; WEAK=$((WEAK + 1))
    fi
else
    echo "  NOT FOUND"
fi
echo

# ---- Account lockout -------------------------------------------------------
echo "Account Lockout:"
lockout=0
for m in pam_faillock pam_tally2; do
    hits=$(grep -lE "^[[:space:]]*[^#].*${m}\.so" "$PAM_DIR"/* 2>/dev/null \
           | xargs -r -n1 basename | tr '\n' ' ')
    if [ -n "$hits" ]; then
        echo "  $m: CONFIGURED (${hits% })"; lockout=1
    else
        echo "  $m: NOT CONFIGURED"
    fi
done
[ "$lockout" -eq 0 ] && WEAK=$((WEAK + 1))
echo

# ---- Password aging --------------------------------------------------------
defs() { awk -v k="$1" '$1 == k {v = $2} END {print v}' "$LOGIN_DEFS" 2>/dev/null; }
max=$(defs PASS_MAX_DAYS); min=$(defs PASS_MIN_DAYS); warn=$(defs PASS_WARN_AGE)
max=${max:-99999}; min=${min:-0}; warn=${warn:-7}

echo "Password Aging:"
if [ "$max" -ge 99999 ]; then
    echo "  Default max days: $max (effectively disabled)"; WEAK=$((WEAK + 1))
elif [ "$max" -gt 90 ]; then
    echo "  Default max days: $max (too long)"; WEAK=$((WEAK + 1))
else
    echo "  Default max days: $max"
fi
echo "  Default min days: $min"
echo "  Default warn days: $warn"
echo

# ---- SSH authentication ----------------------------------------------------
# Effective value: prefer `sshd -T` (needs root), else parse config files
# honouring Include and OpenSSH's "first value wins" rule.
ssh_stream() {
    local file="$1" line inc
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            [[:space:]]*[Mm]atch*|[Mm]atch*) return 1 ;;  # stop at Match blocks
        esac
        if [[ "$line" =~ ^[[:space:]]*[Ii]nclude[[:space:]]+(.*)$ ]]; then
            for inc in ${BASH_REMATCH[1]}; do
                [[ "$inc" != /* ]] && inc="/etc/ssh/$inc"
                for g in $inc; do [ -r "$g" ] && { ssh_stream "$g" || return 1; }; done
            done
        else
            echo "$line"
        fi
    done < "$file"
}

SSHD_T=""
[ "$(id -u)" -eq 0 ] && command -v sshd >/dev/null && SSHD_T=$(sshd -T 2>/dev/null)

ssh_opt() {   # $1 = option (lowercase), $2 = default
    local v=""
    for k in $1; do
        if [ -n "$SSHD_T" ]; then
            v=$(echo "$SSHD_T" | awk -v k="$k" '$1 == k {print $2; exit}')
        elif [ -r "$SSHD_CONFIG" ]; then
            v=$(ssh_stream "$SSHD_CONFIG" | grep -vE '^[[:space:]]*(#|$)' \
                | awk -v k="$k" 'tolower($1) == k {print tolower($2); exit}')
        fi
        [ -n "$v" ] && break
    done
    echo "${v:-$2}"
}

pw=$(ssh_opt "passwordauthentication" yes)
pk=$(ssh_opt "pubkeyauthentication" yes)
cr=$(ssh_opt "challengeresponseauthentication kbdinteractiveauthentication" yes)

echo "SSH Authentication:"
if [ "$pw" = "yes" ]; then
    echo "  PasswordAuthentication: yes (INSECURE)"; WEAK=$((WEAK + 1))
else
    echo "  PasswordAuthentication: $pw"
fi
echo "  PubkeyAuthentication: $pk"
echo "  ChallengeResponseAuthentication: $cr"
echo

# ---- Summary ---------------------------------------------------------------
if [ "$WEAK" -ge 3 ]; then level="WEAK"
elif [ "$WEAK" -ge 1 ]; then level="MODERATE"
else level="STRONG"; fi
echo "Summary: Identity controls are $level"
