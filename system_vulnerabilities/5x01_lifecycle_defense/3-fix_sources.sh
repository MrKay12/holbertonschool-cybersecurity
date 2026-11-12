#!/bin/bash
# 3-fix_sources.sh
# Task: Validate all APT sources and disable invalid/unreachable ones

echo "=== APT Sources Validation ==="

VALID_COUNT=0
DISABLED_COUNT=0

# Function to test a single repository
check_repo() {
    local repo_file="$1"
    local line="$2"

    # Ignore comments and empty lines
    [[ "$line" =~ ^#.*$ || -z "$line" ]] && return 0

    # Extract the URL (assume 'deb http://...' format)
    url=$(echo "$line" | awk '{print $2}')
    if curl -s --head --fail "$url" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# 1. Check /etc/apt/sources.list
echo -e "\nChecking main sources.list..."
MAIN_FILE="/etc/apt/sources.list"
LINE_COUNT=$(grep -v '^#' "$MAIN_FILE" | grep -v '^\s*$' | wc -l)
INVALID_LINES=0
while IFS= read -r line; do
    if ! check_repo "$MAIN_FILE" "$line"; then
        INVALID_LINES=$((INVALID_LINES + 1))
        echo "  $line: INVALID (repository not reachable)"
        # Disable by commenting
        sed -i "s|^$line|# $line|g" "$MAIN_FILE"
        DISABLED_COUNT=$((DISABLED_COUNT + 1))
    else
        VALID_COUNT=$((VALID_COUNT + 1))
    fi
done < "$MAIN_FILE"

if [ $INVALID_LINES -eq 0 ]; then
    echo "  $LINE_COUNT entries: All valid"
fi

# 2. Check /etc/apt/sources.list.d/
echo -e "\nChecking sources.list.d/..."
if [ -d "/etc/apt/sources.list.d/" ]; then
    for file in /etc/apt/sources.list.d/*.list 2>/dev/null; do
        [ -e "$file" ] || continue
        while IFS= read -r line; do
            if [[ "$line" =~ ^#.*$ || -z "$line" ]]; then
                continue
            fi
            if ! check_repo "$file" "$line"; then
                echo "  $(basename "$file"): INVALID (repository not reachable)"
                mv "$file" "$file.disabled"
                echo "    Action: Renamed to $(basename "$file.disabled")"
                DISABLED_COUNT=$((DISABLED_COUNT + 1))
                break
            else
                VALID_COUNT=$((VALID_COUNT + 1))
            fi
        done < "$file"
    done
fi

# 3. Update package lists
echo -e "\nRunning apt update..."
sudo apt update -y >/dev/null 2>&1 && echo "  All repositories updated successfully." || echo "  Some repositories failed."

# 4. Summary
echo -e "\nSummary:"
echo "  Valid sources: $VALID_COUNT"
echo "  Disabled sources: $DISABLED_COUNT"
