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

if [ -e "$KEY" ]; then
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
    if ! ssh-keygen -t ed25519 -a 100 -f "$KEY" -C "$COMMENT" -q; then
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
chmod 600 "$KEY"
chmod 644 "$KEY.pub"
echo "  Private key: $(stat -c %a "$KEY") (owner read/write only)"
echo "  Public key: $(stat -c %a "$KEY.pub")"
echo

echo "Public key fingerprint:"
echo "  $(ssh-keygen -l -f "$KEY.pub" | awk '{print $2}')"
echo

echo "Your public key:"
cat "$KEY.pub"
echo

echo "Next step: Add this public key to target servers' authorized_keys"
echo "  ssh-copy-id -i $KEY.pub user@server"
