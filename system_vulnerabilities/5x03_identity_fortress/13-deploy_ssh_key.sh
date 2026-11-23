#!/bin/bash
# 13-deploy_ssh_key.sh
# Install a public key into the current user's ~/.ssh/authorized_keys
# (what ssh-copy-id does on the server side).
#
# Usage: ./13-deploy_ssh_key.sh "ssh-ed25519 AAAA... user@host"
#
# - The key is validated with ssh-keygen before being written.
# - A key already present (same type + key data) is not added twice.
# - sshd's StrictModes rejects keys in group/world-writable files, so the
#   directory is set to 700 and the file to 600.

if [ $# -eq 0 ] || [ -z "$1" ]; then
    echo "Usage: $0 \"ssh-ed25519 AAAA... user@host\"" >&2
    exit 1
fi
if [ $# -gt 1 ]; then
    echo "Error: quote the key so it is one argument: $0 \"ssh-ed25519 AAAA... user@host\"" >&2
    exit 1
fi

USER_NAME=$(whoami)

echo "=== SSH Key Deployment ==="
echo
echo "Target user: $USER_NAME"
echo

# ---- 1. Validate the key ---------------------------------------------------
tmp=$(mktemp) || exit 1
trap 'rm -f "$tmp"' EXIT
printf '%s\n' "$1" > "$tmp"
fingerprint=$(ssh-keygen -lf "$tmp" 2>/dev/null | awk '{print $2}')
if [ -z "$fingerprint" ]; then
    echo "Error: not a valid SSH public key" >&2
    exit 1
fi
# "type base64" identifies the key; the trailing comment does not
key_id=$(awk '{print $1, $2}' "$tmp")

# ---- 2. ~/.ssh -------------------------------------------------------------
echo "Creating .ssh directory if needed..."
if [ -d $HOME/.ssh ]; then
    echo "  $HOME/.ssh: Already exists"
else
    mkdir -p $HOME/.ssh
    echo "  $HOME/.ssh: Created"
fi
chmod 700 $HOME/.ssh
echo "  Permissions: $(stat -c %a $HOME/.ssh)"
echo

# ---- 3. authorized_keys ----------------------------------------------------
echo "Adding key to authorized_keys..."
echo "  Key fingerprint: $fingerprint"
touch $HOME/.ssh/authorized_keys
if awk '{print $1, $2}' $HOME/.ssh/authorized_keys | grep -qxF "$key_id"; then
    echo "  Key already present, not added again"
else
    # make sure the previous last line ends with a newline
    [ -s $HOME/.ssh/authorized_keys ] && [ -n "$(tail -c1 $HOME/.ssh/authorized_keys)" ] \
        && echo >> $HOME/.ssh/authorized_keys
    echo "$1" >> $HOME/.ssh/authorized_keys
    echo "  Key added successfully"
fi
echo

echo "Setting permissions..."
chmod 600 $HOME/.ssh/authorized_keys
echo "  authorized_keys: $(stat -c %a $HOME/.ssh/authorized_keys)"
echo

# ---- 4. Verify -------------------------------------------------------------
count=$(grep -cvE '^[[:space:]]*(#|$)' $HOME/.ssh/authorized_keys)
present=$(awk '{print $1, $2}' $HOME/.ssh/authorized_keys | grep -cxF "$key_id")
perms_ok="NO"
if [ "$(stat -c %a $HOME/.ssh)" = "700" ] \
   && [ "$(stat -c %a $HOME/.ssh/authorized_keys)" = "600" ] \
   && [ "$(stat -c %U $HOME/.ssh/authorized_keys)" = "$USER_NAME" ]; then
    perms_ok="YES"
fi
echo "Verification:"
echo "  Key count in authorized_keys: $count"
echo "  Permissions correct: $perms_ok"
echo

if [ "$present" -ge 1 ] && [ "$perms_ok" = "YES" ]; then
    echo "SSH key deployed."
    echo "User can now authenticate with this key."
else
    echo "SSH key deployment FAILED"
    exit 1
fi
