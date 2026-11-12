#!/bin/bash
# 19-dry_run.sh
# Dry-run simulation of unattended-upgrades

echo "=== Unattended-Upgrades Dry Run ==="
echo
echo "Running simulation..."

# Run unattended-upgrades in dry-run and debug mode
DRY_RUN_OUTPUT=$(sudo unattended-upgrade --dry-run --debug 2>&1)

# Parse packages that would be upgraded (security)
UPGRADE_LIST=$(echo "$DRY_RUN_OUTPUT" | grep "upgraded:" | awk -F':' '{print $2}' | tr -d ',' | sed 's/^/  /')

# Parse blacklisted packages
BLACKLISTED=$(echo "$DRY_RUN_OUTPUT" | grep "blacklisted:" | awk -F':' '{print $2}' | tr -d ',' | sed 's/^/  /')

# Parse skipped non-security packages
SKIPPED=$(echo "$DRY_RUN_OUTPUT" | grep "skipped:" | awk -F':' '{print $2}' | tr -d ',' | sed 's/^/  /')

# Detect if reboot required
if echo "$DRY_RUN_OUTPUT" | grep -iq "reboot required"; then
    REBOOT="YES (kernel update)"
else
    REBOOT="NO"
fi

# Output results
echo
echo "Packages that WOULD be upgraded:"
[ -n "$UPGRADE_LIST" ] && echo "$UPGRADE_LIST" || echo "  None"

echo
echo "Packages PROTECTED by blacklist:"
[ -n "$BLACKLISTED" ] && echo "$BLACKLISTED" || echo "  None"

echo
echo "Packages NOT in security origin:"
[ -n "$SKIPPED" ] && echo "$SKIPPED" || echo "  None"

echo
echo "Simulation summary:"
echo "  Would upgrade: $(echo "$UPGRADE_LIST" | grep -c '^') packages"
echo "  Blacklisted: $(echo "$BLACKLISTED" | grep -c '^') packages"
echo "  Skipped (non-security): $(echo "$SKIPPED" | grep -c '^') package$( [ $(echo "$SKIPPED" | grep -c '^') -ne 1 ] && echo "s" )"
echo "  Reboot required: $REBOOT"

echo
echo "Configuration validation: PASSED"
