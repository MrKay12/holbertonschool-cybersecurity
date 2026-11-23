#!/bin/bash
# 16-install_google_auth.sh
# Install the Google Authenticator PAM module (TOTP for SSH and any other
# PAM service) and check that the module and the enrollment tool are there.
#
# Nothing is enabled yet: PAM and sshd are configured in the next tasks,
# after users have enrolled (or they would be locked out).

lock_files="/var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run with sudo (sudo $0)" >&2
    exit 1
fi

echo "=== Google Authenticator Installation ==="
echo

# ---- apt/dpkg preparation (same as 2-password_complexity.sh) ---------------
pkg_busy() {
    pgrep -x 'apt|apt-get|aptitude|dpkg|unattended-upgr' >/dev/null && return 0
    fuser $lock_files >/dev/null 2>&1 && return 0
    return 1
}
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
    for l in $lock_files; do [ -e "$l" ] && rm -f "$l"; done
    [ -n "$(dpkg --audit 2>/dev/null)" ] && dpkg --configure -a >/dev/null 2>&1
    if ! apt-get check >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get install -f -y -qq >/dev/null 2>&1
    fi
    if [ -n "$(dpkg --audit 2>/dev/null)" ] || ! apt-get check >/dev/null 2>&1; then
        echo "  Error: broken packages remain (see: dpkg --audit; apt-get check)" >&2
        exit 1
    fi
}

# ---- 1. Install ------------------------------------------------------------
echo "Installing libpam-google-authenticator..."
if dpkg-query -W -f='${Status}' libpam-google-authenticator 2>/dev/null | grep -q "ok installed"; then
    echo "  Package: Already installed"
else
    prepare_apt
    if DEBIAN_FRONTEND=noninteractive apt install -y libpam-google-authenticator >/dev/null 2>&1; then
        echo "  Package: Installed"
    else
        echo "  Error: failed to install libpam-google-authenticator" >&2
        exit 1
    fi
fi
echo

# ---- 2. Verify -------------------------------------------------------------
# Ask the package where it put the module (path depends on the architecture)
module=$(dpkg -L libpam-google-authenticator | grep '/pam_google_authenticator\.so$' | head -1)
echo "Module location:"
if [ -n "$module" ] && [ -f "$module" ]; then
    echo "  $module"
else
    echo "  Error: pam_google_authenticator.so not found" >&2
    exit 1
fi
if ! command -v google-authenticator >/dev/null; then
    echo "  Error: google-authenticator command not found" >&2
    exit 1
fi
echo

echo "Next steps:"
echo "  1. Run 'google-authenticator' as each user to generate secrets"
echo "  2. Configure /etc/pam.d/sshd to require the module"
echo "  3. Enable ChallengeResponseAuthentication in sshd_config"
echo "     (KbdInteractiveAuthentication on OpenSSH 8.7+)"
echo

echo "Google Authenticator PAM module: INSTALLED"
