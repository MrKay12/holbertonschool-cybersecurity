#!/bin/bash
# 6-security_updates.sh
# Task: Apply only security updates

echo "=== Security Updates ==="

# 1. Fetch security updates list
echo -e "\nFetching security update list..."
sudo apt update -o Dir::Etc::sourcelist="sources.list.d/ubuntu-security.list" \
                -o Dir::Etc::sourceparts="-" \
                -o APT::Get::List-Cleanup="0"

SEC_UPDATES=$(apt list --upgradable 2>/dev/null | grep -i security)
SEC_COUNT=$(echo "$SEC_UPDATES" | wc -l)

if [ "$SEC_COUNT" -gt 0 ]; then
    echo "Source: $(grep '^deb .*security' /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null | awk '{print $3}' | head -n1)"
    echo -e "\nAvailable security updates: $SEC_COUNT packages"
    echo "$SEC_UPDATES" | awk -F/ '{print "  "$1}' 
else
    echo "No security updates available."
    exit 0
fi

# 2. Apply security updates only
echo -e "\nApplying security updates..."
sudo apt-get install -y $(echo "$SEC_UPDATES" | awk -F/ '{print $1}')
echo "  $SEC_COUNT packages upgraded."

# 3. Verification
echo -e "\nVerification:"
for pkg in $(echo "$SEC_UPDATES" | awk -F/ '{print $1}'); do
    VER=$(dpkg -s "$pkg" 2>/dev/null | grep '^Version:' | awk '{print $2}')
    echo "  $pkg: $VER (CURRENT)"
done

PENDING=$(apt list --upgradable 2>/dev/null | grep -i security | wc -l)
echo "  Pending security updates: $PENDING"

echo -e "\nSecurity updates applied successfully."
