#!/bin/bash
# 21-lock_root.sh
# Lock the root password so all privileged access goes through sudo.
# Aborts if the calling user does not have working sudo access.

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run with sudo (sudo $0)" >&2
    exit 1
fi

ADMIN="$SUDO_USER"

echo "=== Root Account Lockdown ==="
echo
echo "Pre-flight checks:"

# 1. The calling user must be a real user with sudo rights (not root itself)
if [ -n "$ADMIN" ] && [ "$ADMIN" != "root" ] && \
   sudo -l -U "$ADMIN" 2>/dev/null | grep -qE '\(ALL( : ALL)?\) (NOPASSWD: )?ALL'; then
    echo "  Current user has sudo: YES ✓"
else
    echo "  Current user has sudo: NO ✗"
    echo
    echo "Aborting: run this script with sudo from an admin account,"
    echo "otherwise locking root could lock you out of the system."
    exit 1
fi

# 2. The sudoers configuration must be valid
if visudo -c >/dev/null 2>&1; then
    echo "  Sudo configuration valid: YES ✓"
else
    echo "  Sudo configuration valid: NO ✗"
    echo
    echo "Aborting: fix sudoers first (visudo -c)."
    exit 1
fi

echo
echo "Locking root account..."
if passwd -l root >/dev/null 2>&1; then
    echo "  passwd -l root: Done"
else
    echo "  passwd -l root: FAILED"
    exit 1
fi

echo
echo "Verification:"

# Root password: locked when the hash starts with '!'
if [ "$(passwd -S root | awk '{print $2}')" = "L" ]; then
    echo "  Root password: LOCKED (!)"
else
    echo "  Root password: NOT LOCKED ✗"
fi

# Root SSH login
PRL=$(sshd -T 2>/dev/null | awk '/^permitrootlogin/ {print $2}')
case "$PRL" in
    no)  echo "  Root SSH login: Already disabled (PermitRootLogin no)" ;;
    "")  echo "  Root SSH login: sshd not installed" ;;
    *)   echo "  Root SSH login: ENABLED (PermitRootLogin $PRL) - set it to 'no'" ;;
esac

# Sudo to root still works for the admin user
if sudo -l -U "$ADMIN" 2>/dev/null | grep -qE '\(ALL( : ALL)?\) (NOPASSWD: )?ALL'; then
    echo "  Sudo to root: WORKING ✓"
else
    echo "  Sudo to root: BROKEN ✗ - unlock with: passwd -u root"
    exit 1
fi

echo
echo "WARNING: Direct root login is now impossible."
echo "All administrative tasks must use sudo."
