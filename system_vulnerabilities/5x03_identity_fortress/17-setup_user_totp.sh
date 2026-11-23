#!/bin/bash
# 17-setup_user_totp.sh
# Generate the current user's TOTP secret with google-authenticator, using
# secure defaults:
#   -t          time-based tokens (TOTP)
#   -d          disallow token reuse
#   -r 3 -R 30  rate limit: 3 logins per 30 seconds
#   -w 3        window of 3 codes (tolerates small clock skew)
#   -e 5        5 emergency scratch codes
#   -f          write ~/.google_authenticator without asking
#
# google-authenticator prints the secret, QR code and scratch codes, then
# asks for a code from the app to confirm it was scanned correctly.
#
# Usage: ./17-setup_user_totp.sh [--force]
#   Run as the user to enroll (no sudo). --force replaces an existing
#   secret, which invalidates the app already configured for it.

GA_FILE="$HOME/.google_authenticator"

if [ -n "$SUDO_USER" ] && [ "$(id -u)" -eq 0 ]; then
    echo "Error: run as the user to enroll, without sudo (this would enroll root)" >&2
    exit 1
fi
if ! command -v google-authenticator >/dev/null; then
    echo "Error: google-authenticator not found (run sudo ./16-install_google_auth.sh)" >&2
    exit 1
fi
if [ -e "$GA_FILE" ] && [ "$1" != "--force" ]; then
    echo "Error: $GA_FILE already exists; your authenticator app uses it." >&2
    echo "Re-run with --force to generate a NEW secret (the old one stops working)." >&2
    exit 1
fi

echo "=== TOTP Setup for Current User ==="
echo
echo "Running google-authenticator with secure defaults..."
echo

# --force: keep the old secret aside, restore it if enrollment fails
if [ -e "$GA_FILE" ]; then
    mv -f "$GA_FILE" "$GA_FILE.old"
fi

if ! google-authenticator -t -d -f -r 3 -R 30 -w 3 -e 5; then
    echo "Error: google-authenticator failed" >&2
    [ -e "$GA_FILE.old" ] && mv -f "$GA_FILE.old" "$GA_FILE" \
        && echo "Previous secret restored." >&2
    exit 1
fi
echo

if [ ! -s "$GA_FILE" ]; then
    echo "Error: $GA_FILE was not created" >&2
    exit 1
fi
# The secret must stay private (pam_google_authenticator checks this)
chmod 400 "$GA_FILE"
echo "Configuration saved to ~/.google_authenticator"
echo

# Read the settings back from the saved file
has() { grep -q "^\" $1" "$GA_FILE"; }
rate=$(sed -nE 's/^" RATE_LIMIT ([0-9]+) ([0-9]+).*/\1 logins per \2 seconds/p' "$GA_FILE")
window=$(sed -nE 's/^" WINDOW_SIZE ([0-9]+).*/\1/p' "$GA_FILE")
echo "Settings applied:"
has TOTP_AUTH && echo "  Time-based tokens: YES" || echo "  Time-based tokens: NO"
echo "  Rate limiting: ${rate:-NONE}"
has DISALLOW_REUSE && echo "  Token reuse: DISALLOWED" || echo "  Token reuse: ALLOWED"
echo "  Window size: ${window:-default} (allows clock skew)"
echo

echo "IMPORTANT: Save your emergency codes securely!"
echo "Scan the QR code with your authenticator app."
