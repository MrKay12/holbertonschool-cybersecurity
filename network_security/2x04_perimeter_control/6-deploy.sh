#!/bin/bash

TARGET="$1"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 user@host"
    exit 1
fi

scp skeleton.conf 2-panic.sh "$TARGET:~/"

ssh "$TARGET" <<'EOF'
chmod +x ~/2-panic.sh
~/2-panic.sh
sudo nft -f ~/skeleton.conf
sudo nft list ruleset
EOF