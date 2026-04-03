#!/bin/bash
f="$1"

sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/; s/^#\?PasswordAuthentication.*/PasswordAuthentication no/; s/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' "$f"

grep -q '^PermitRootLogin' "$f" || echo 'PermitRootLogin no' >> "$f"
grep -q '^PasswordAuthentication' "$f" || echo 'PasswordAuthentication no' >> "$f"
grep -q '^PubkeyAuthentication' "$f" || echo 'PubkeyAuthentication yes' >> "$f"

sshd -t -f "$f" && (systemctl reload sshd 2>/dev/null || systemctl reload ssh)
