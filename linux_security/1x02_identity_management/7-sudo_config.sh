#!/bin/bash
f="/etc/sudoers.d/junior"

echo "$1 ALL=(ALL) /usr/bin/systemctl restart apache2, /usr/bin/journalctl" > "$f"
chmod 440 "$f"

visudo -c -f "$f"
