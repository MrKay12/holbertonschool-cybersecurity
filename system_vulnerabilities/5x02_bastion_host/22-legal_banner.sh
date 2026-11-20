#!/bin/bash
# 22-legal_banner.sh
# Configure a legal warning banner shown before SSH login.

BANNER_FILE="/etc/issue.net"
SSHD_CONFIG="/etc/ssh/sshd_config"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run as root (sudo $0)" >&2
    exit 1
fi

if [ ! -f "$SSHD_CONFIG" ]; then
    echo "Error: $SSHD_CONFIG not found (is openssh-server installed?)" >&2
    exit 1
fi

echo "=== Legal Banner Configuration ==="
echo
echo "Creating banner in $BANNER_FILE..."
cat > "$BANNER_FILE" <<'EOF'
=====================================
AUTHORIZED ACCESS ONLY

This system is the property of NovaTech Solutions.
Unauthorized access is prohibited and will be prosecuted.
All activities are monitored and logged.
=====================================
EOF
chown root:root "$BANNER_FILE"
chmod 644 "$BANNER_FILE"

echo
echo "Banner content:"
cat "$BANNER_FILE"

echo
echo "Configuring SSH to display banner..."
cp "$SSHD_CONFIG" "$SSHD_CONFIG.bak.$(date +%Y%m%d%H%M%S)"
if grep -qiE '^[[:space:]]*#?[[:space:]]*Banner[[:space:]]' "$SSHD_CONFIG"; then
    # Replace the existing (possibly commented) Banner line
    sed -i -E "0,/^[[:space:]]*#?[[:space:]]*Banner[[:space:]].*/s||Banner $BANNER_FILE|" "$SSHD_CONFIG"
else
    echo "Banner $BANNER_FILE" >> "$SSHD_CONFIG"
fi
echo "  Banner $BANNER_FILE: Enabled"

echo
echo "Reloading SSH..."
if ! sshd -t; then
    echo "  sshd configuration invalid - not reloading" >&2
    exit 1
fi
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null

echo
echo "Verification:"
OK=1
if [ -s "$BANNER_FILE" ]; then
    echo "  $BANNER_FILE: EXISTS ✓"
else
    echo "  $BANNER_FILE: MISSING ✗"
    OK=0
fi

if [ "$(sshd -T 2>/dev/null | awk '/^banner / {print $2}')" = "$BANNER_FILE" ]; then
    echo "  SSH Banner config: ENABLED ✓"
else
    echo "  SSH Banner config: NOT ACTIVE ✗ (check $SSHD_CONFIG.d/)"
    OK=0
fi

echo
if [ "$OK" -eq 1 ]; then
    echo "Legal banner configured."
else
    echo "Legal banner configuration FAILED."
    exit 1
fi
