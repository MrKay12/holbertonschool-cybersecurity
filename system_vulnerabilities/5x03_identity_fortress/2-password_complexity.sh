#!/bin/bash
# 2-password_complexity.sh
# Configure pam_pwquality to enforce strong passwords:
#   12+ chars, upper + lower + digit + special, no username,
#   at least 3 characters different from the old password.

PWQ_CONF="/etc/security/pwquality.conf"
PAM_PASSWORD="/etc/pam.d/common-password"
lock_files="/var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run with sudo (sudo $0)" >&2
    exit 1
fi

echo "=== Password Complexity Configuration ==="
echo

# ---- apt/dpkg lock handling ------------------------------------------------
pkg_busy() {
    # Running package manager processes
    pgrep -x 'apt|apt-get|aptitude|dpkg|unattended-upgr' >/dev/null && return 0
    # A process still holding one of the lock files
    fuser $lock_files >/dev/null 2>&1 && return 0
    return 1
}

# Wait for a running apt/dpkg to finish, then clear stale locks and verify
prepare_apt() {
    local i l
    for i in $(seq 1 60); do
        pkg_busy || break
        [ "$i" -eq 1 ] && echo "  Waiting for running apt/dpkg to finish..."
        sleep 5
    done
    if pkg_busy; then
        echo "  Error: apt/dpkg still running after 5 minutes, aborting" >&2
        exit 1
    fi
    # Nothing is running, so any lock file left behind is stale
    for l in $lock_files; do
        [ -e "$l" ] && rm -f "$l"
    done
    # Verify: no lock left, nobody grabbed one, dpkg database consistent
    for l in $lock_files; do
        if [ -e "$l" ]; then
            echo "  Error: could not remove lock $l" >&2
            exit 1
        fi
    done
    if pkg_busy; then
        echo "  Error: package manager started during lock cleanup" >&2
        exit 1
    fi
    # Repair: finish an interrupted dpkg run, then fix broken dependencies
    if [ -n "$(dpkg --audit 2>/dev/null)" ]; then
        echo "  Repairing interrupted dpkg run..."
        dpkg --configure -a >/dev/null 2>&1
    fi
    if ! apt-get check >/dev/null 2>&1; then
        echo "  Fixing broken dependencies..."
        DEBIAN_FRONTEND=noninteractive apt-get install -f -y -qq >/dev/null 2>&1
    fi
    # Verify the repair: no half-configured packages, no broken dependencies
    if [ -n "$(dpkg --audit 2>/dev/null)" ] || ! apt-get check >/dev/null 2>&1; then
        echo "  Error: broken packages remain (see: dpkg --audit; apt-get check)" >&2
        exit 1
    fi
}

installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "ok installed"; }

# ---- 1. Install ------------------------------------------------------------
echo "Installing libpam-pwquality..."
# libpwquality-tools provides pwscore, used for the enforcement test
missing=""
for p in libpam-pwquality libpwquality-tools; do
    installed "$p" || missing="$missing $p"
done
installed libpam-pwquality && echo "  Already installed: libpam-pwquality"
if [ -n "$missing" ]; then
    prepare_apt
    if DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $missing >/dev/null 2>&1; then
        echo "  Installed:$missing"
    else
        echo "  Error: failed to install$missing" >&2
        exit 1
    fi
fi
echo

# ---- 2. Backup -------------------------------------------------------------
echo "Backing up configuration..."
for f in "$PWQ_CONF" "$PAM_PASSWORD"; do
    if [ -f "$f" ]; then
        cp -p "$f" "$f.backup" && echo "  $f.backup created"
    fi
done
echo

# ---- 3. pwquality.conf -----------------------------------------------------
# Replace "key = value" (commented or not), or append it if absent
set_conf() {
    local key="$1" val="$2"
    if grep -qE "^[[:space:]]*#?[[:space:]]*$key[[:space:]]*=" "$PWQ_CONF"; then
        sed -i -E "s|^[[:space:]]*#?[[:space:]]*$key[[:space:]]*=.*|$key = $val|" "$PWQ_CONF"
    else
        echo "$key = $val" >> "$PWQ_CONF"
    fi
}

touch "$PWQ_CONF"
echo "Configuring $PWQ_CONF:"
set_conf minlen 12;    echo "  minlen = 12"
set_conf dcredit -1;   echo "  dcredit = -1 (require digit)"
set_conf ucredit -1;   echo "  ucredit = -1 (require uppercase)"
set_conf lcredit -1;   echo "  lcredit = -1 (require lowercase)"
set_conf ocredit -1;   echo "  ocredit = -1 (require special)"
set_conf usercheck 1;  echo "  usercheck = 1 (reject username in password)"
set_conf difok 3;      echo "  difok = 3 (must differ from old password)"
echo

# ---- 4. PAM stack ----------------------------------------------------------
echo "Updating $PAM_PASSWORD..."
if ! grep -qE '^[[:space:]]*password.*pam_pwquality\.so' "$PAM_PASSWORD"; then
    # Debian/Ubuntu way: let pam-auth-update enable the pwquality profile
    command -v pam-auth-update >/dev/null && \
        pam-auth-update --package --enable pwquality >/dev/null 2>&1
fi
if ! grep -qE '^[[:space:]]*password.*pam_pwquality\.so' "$PAM_PASSWORD"; then
    # Fallback: insert before pam_unix, and make pam_unix reuse the
    # password pam_pwquality already validated
    sed -i -E '0,/^[[:space:]]*password.*pam_unix\.so/s//password\trequisite\t\t\tpam_pwquality.so retry=3\n&/' "$PAM_PASSWORD"
    sed -i -E '/^[[:space:]]*password.*pam_unix\.so/{/use_authtok/!s/pam_unix\.so/pam_unix.so use_authtok/}' "$PAM_PASSWORD"
fi
if grep -qE '^[[:space:]]*password.*pam_pwquality\.so' "$PAM_PASSWORD"; then
    echo "  pam_pwquality.so: Configured"
else
    echo "  pam_pwquality.so: FAILED (restore $PAM_PASSWORD.backup)" >&2
    exit 1
fi
echo

# ---- 5. Test ---------------------------------------------------------------
# pwscore applies pwquality.conf exactly as pam_pwquality does
echo "Testing enforcement..."
ok=1
for pw in "weak" "Password123"; do
    if echo "$pw" | pwscore >/dev/null 2>&1; then
        echo "  Attempt \"$pw\": ACCEPTED ✗"; ok=0
    else
        echo "  Attempt \"$pw\": REJECTED ✓"
    fi
done
echo

if [ "$ok" -eq 1 ]; then
    echo "Password complexity enforcement: ACTIVE"
else
    echo "Password complexity enforcement: NOT EFFECTIVE"
    exit 1
fi
