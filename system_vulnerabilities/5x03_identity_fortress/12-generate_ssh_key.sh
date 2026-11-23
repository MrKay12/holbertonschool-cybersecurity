#!/bin/bash
# 12-generate_ssh_key.sh
# Generate an ED25519 SSH key pair for the current user.
#
# - ED25519: small, fast, no weak-parameter pitfalls (unlike RSA/ECDSA).
# - -a 100: 100 KDF rounds, so a stolen private key's passphrase is slow
#   to brute-force.
# - An existing key is never overwritten (servers may already trust it).
#
# Run as the user who will own the key (no sudo).

SSH_DIR="$HOME/.ssh"
KEY="$SSH_DIR/id_ed25519"
COMMENT="$(whoami)@$(hostname)"

echo "=== SSH Key Generation ==="
echo

# ~/.ssh must be private or sshd ignores the keys in it
mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"

if [ -e $HOME/.ssh/id_ed25519 ]; then
    echo "Existing key found: $KEY"
    echo "  Not overwriting it (servers may already trust this key)."
    echo "  To replace it, move it away first: mv $KEY $KEY.old"
else
    echo "Generating ED25519 key pair..."
    echo "  Algorithm: ED25519 (recommended)"
    echo "  Key file: ~/.ssh/id_ed25519"
    echo
    echo "Enter passphrase (recommended):"
    # ssh-keygen asks for the passphrase twice itself
    if ! ssh-keygen -t ed25519 -a 100 -f $HOME/.ssh/id_ed25519 -C "$COMMENT" -q; then
        echo "Error: key generation failed" >&2
        exit 1
    fi
    echo
    echo "Key pair generated:"
fi
echo "  Private key: $KEY"
echo "  Public key: $KEY.pub"
echo

echo "Setting permissions..."
chmod 600 $HOME/.ssh/id_ed25519
chmod 644 $HOME/.ssh/id_ed25519.pub
echo "  Private key: $(stat -c %a $HOME/.ssh/id_ed25519) (owner read/write only)"
echo "  Public key: $(stat -c %a $HOME/.ssh/id_ed25519.pub)"
echo

echo "Public key fingerprint:"
echo "  $(ssh-keygen -l -f $HOME/.ssh/id_ed25519.pub | awk '{print $2}')"
echo

echo "Your public key:"
cat $HOME/.ssh/id_ed25519.pub
echo

echo "Next step: Add this public key to target servers' authorized_keys"
echo "  ssh-copy-id -i $KEY.pub user@server"
