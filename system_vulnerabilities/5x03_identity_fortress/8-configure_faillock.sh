#!/bin/bash
# 8-configure_faillock.sh
# Account lockout with pam_faillock: lock after 5 failed attempts within
# 15 minutes, for 15 minutes.
#
# root is NOT locked (no even_deny_root): it stays the emergency access path.
# All three files are backed up to *.bak; if a correct password stops
# working after the change, the backups are restored automatically.
#
# Note: running pam-auth-update later regenerates common-auth/common-account
# and drops these lines; re-run this script afterwards.

TEST_USER="testuser"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run with sudo (sudo $0)" >&2
    exit 1
fi

echo "=== Account Lockout Configuration ==="
echo
echo "Configuring pam_faillock..."
cp /etc/pam.d/common-auth /etc/pam.d/common-auth.bak || exit 1
cp /etc/pam.d/common-account /etc/pam.d/common-account.bak || exit 1
[ -f /etc/security/faillock.conf ] && cp /etc/security/faillock.conf /etc/security/faillock.conf.bak
echo

restore() {
    cp /etc/pam.d/common-auth.bak /etc/pam.d/common-auth
    cp /etc/pam.d/common-account.bak /etc/pam.d/common-account
    [ -f /etc/security/faillock.conf.bak ] && cp /etc/security/faillock.conf.bak /etc/security/faillock.conf
}

# Insert a PAM rule into a file, before or after the rule number <pos>,
# and renumber jump actions ([success=N ...]) of earlier rules whose
# target lies at or past the insertion point, so the stack logic is kept.
#   pam_insert <file> <before|after> <regex of anchor rule> <new rule>
pam_insert() {
    local file="$1" where="$2" anchor="$3" rule="$4" tmp
    tmp=$(mktemp) || return 1
    awk -v where="$where" -v anchor="$anchor" -v rule="$rule" '
        function fix(s, k, p,    pre, mid, post, out, m, n) {
            # only touch the [...] control field
            if (!match(s, /\[[^]]*\]/)) return s
            pre = substr(s, 1, RSTART - 1); mid = substr(s, RSTART, RLENGTH)
            post = substr(s, RSTART + RLENGTH); out = ""
            while (match(mid, /=[0-9]+/)) {
                n = substr(mid, RSTART + 1, RLENGTH - 1) + 0
                if (k + n + 1 >= p) n++       # target moved by the insert
                out = out substr(mid, 1, RSTART) n
                mid = substr(mid, RSTART + RLENGTH)
            }
            return pre out mid post
        }
        { line[NR] = $0 }
        END {
            n = 0
            for (l = 1; l <= NR; l++)
                if (line[l] !~ /^[[:space:]]*(#|$)/) { n++; rl[n] = l }
            a = 0
            for (k = 1; k <= n; k++) if (line[rl[k]] ~ anchor) { a = k; break }
            if (!a) exit 2
            p = (where == "before") ? a : a + 1      # rule index of new line
            for (k = 1; k < p; k++) line[rl[k]] = fix(line[rl[k]], k, p)
            for (l = 1; l <= NR; l++) {
                if (where == "before" && l == rl[a]) print rule
                print line[l]
                if (where == "after" && l == rl[a]) print rule
            }
        }' "$file" > "$tmp" && cat "$tmp" > "$file"
    local rc=$?
    rm -f "$tmp"
    return $rc
}

has_rule() { grep -vE '^[[:space:]]*#' "$2" | grep -qE "$1"; }

# ---- 1. common-auth --------------------------------------------------------
# preauth: refuse early if already locked. authfail: record a failure.
echo "Updating /etc/pam.d/common-auth..."
if has_rule 'pam_faillock\.so.*preauth' /etc/pam.d/common-auth; then
    echo "  pam_faillock.so preauth: Already present"
else
    pam_insert /etc/pam.d/common-auth before '^[[:space:]]*auth' \
        "auth	required			pam_faillock.so preauth" \
        && echo "  pam_faillock.so preauth: Added"
fi
if has_rule 'pam_faillock\.so.*authfail' /etc/pam.d/common-auth; then
    echo "  pam_faillock.so authfail: Already present"
else
    # Right before pam_deny: reached only once every backend (unix, sss,
    # krb5, ...) has failed. Fallback: right after pam_unix.
    authfail="auth	[default=die]			pam_faillock.so authfail"
    if has_rule '^[[:space:]]*auth.*pam_deny[.]so' /etc/pam.d/common-auth; then
        pam_insert /etc/pam.d/common-auth before '^[[:space:]]*auth.*pam_deny[.]so' "$authfail"
    else
        pam_insert /etc/pam.d/common-auth after '^[[:space:]]*auth.*pam_unix[.]so' "$authfail"
    fi && echo "  pam_faillock.so authfail: Added"
fi
echo

# ---- 2. common-account -----------------------------------------------------
# Clears the failure count after a successful login. Appended at the end,
# so no existing jump is affected.
echo "Updating /etc/pam.d/common-account..."
if has_rule 'pam_faillock\.so' /etc/pam.d/common-account; then
    echo "  pam_faillock.so: Already present"
else
    printf 'account\trequired\t\t\tpam_faillock.so\n' >> /etc/pam.d/common-account
    echo "  pam_faillock.so: Added"
fi
echo

# Verify all three rules with grep
if ! grep -E 'pam_faillock.so' /etc/pam.d/common-auth | grep -q preauth \
   || ! grep -E 'pam_faillock.so' /etc/pam.d/common-auth | grep -q authfail \
   || ! grep -qE 'pam_faillock.so' /etc/pam.d/common-account; then
    echo "Error: PAM rules missing, restoring backups" >&2
    restore
    exit 1
fi

# ---- 3. faillock.conf ------------------------------------------------------
echo "Configuration:"
echo "  deny = 5 (lock after 5 failures)"
echo "  unlock_time = 900 (15 minutes)"
echo "  fail_interval = 900 (count failures within 15 min)"
echo

set_conf() {   # replace "key = value" (commented or not), else append
    if grep -qE "^[[:space:]]*#?[[:space:]]*$1[[:space:]]*=" /etc/security/faillock.conf; then
        sed -i -E "s|^[[:space:]]*#?[[:space:]]*$1[[:space:]]*=.*|$1 = $2|" /etc/security/faillock.conf
    else
        echo "$1 = $2" >> /etc/security/faillock.conf
    fi
}
echo "Creating /etc/security/faillock.conf..."
touch /etc/security/faillock.conf
set_conf deny 5
set_conf unlock_time 900
set_conf fail_interval 900
if grep -qE '^deny = 5' /etc/security/faillock.conf \
   && grep -qE '^unlock_time = 900' /etc/security/faillock.conf \
   && grep -qE '^fail_interval = 900' /etc/security/faillock.conf; then
    echo "  Configuration written"
else
    echo "  Error: faillock.conf not updated, restoring backups" >&2
    restore
    exit 1
fi
echo

# ---- 4. Test ---------------------------------------------------------------
# Throwaway user. Logins are attempted with su run as an unprivileged user
# (nobody), so the full auth stack is used. Order:
#   1. correct password works   (else: config broke auth -> restore)
#   2. 5 wrong passwords        -> 5 failures recorded
#   3. correct password refused -> account really locked
echo "Testing..."
if id "$TEST_USER" >/dev/null 2>&1; then
    echo "  Error: user '$TEST_USER' already exists; skipping test" >&2
    exit 1
fi
cleanup() {
    faillock --user "$TEST_USER" --reset >/dev/null 2>&1
    userdel -r "$TEST_USER" >/dev/null 2>&1
}
trap cleanup EXIT

GOOD_PW="Lock!$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 12)7q"
useradd -m -s /bin/bash "$TEST_USER" || exit 1
echo "$TEST_USER:$GOOD_PW" | chpasswd

try_login() {   # exit 0 if authentication succeeded
    printf '%s\n' "$1" \
        | timeout 10 runuser -u nobody -- su "$TEST_USER" -c true >/dev/null 2>&1
}

if ! try_login "$GOOD_PW"; then
    echo "  Error: a correct password is refused, restoring backups" >&2
    restore
    exit 1
fi
faillock --user "$TEST_USER" --reset

echo "  Simulating 5 failed logins for $TEST_USER"
for i in 1 2 3 4 5; do
    try_login "wrong-password-$i"
done

fails=$(faillock --user "$TEST_USER" | grep -cE '[[:space:]]V$')
if [ "$fails" -ge 5 ] && ! try_login "$GOOD_PW"; then
    echo "  Account status: LOCKED"
    echo
    echo "Account lockout: ACTIVE"
else
    echo "  Account status: NOT LOCKED ($fails failures recorded)"
    echo
    echo "Account lockout: NOT EFFECTIVE"
    exit 1
fi
