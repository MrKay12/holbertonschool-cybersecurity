#!/bin/bash
# 23-manage_holds.sh
# Manage package holds: list or release

LOG_FILE="/var/log/package_holds.log"

if [ -z "$1" ]; then
    echo "Usage: $0 <list|release> [package]"
    exit 1
fi

COMMAND="$1"

list_holds() {
    echo "=== Package Hold Registry ==="
    printf "%-15s %-10s %-12s %-4s %s\n" "Package" "Version" "Held Since" "Days" "Reason"

    TOTAL=0
    OLD=0
    TODAY=$(date +%s)

    while IFS='|' read -r ts pkg rest; do
        ts=$(echo "$ts" | xargs)
        pkg=$(echo "$pkg" | xargs)
        version=$(echo "$rest" | awk -F'|' '{print $2}' | awk -F':' '{print $2}' | xargs)
        reason=$(echo "$rest" | awk -F'|' '{print $1}' | awk -F':' '{print $2}' | xargs)
        HELD_SINCE=$(date -d "$ts" '+%Y-%m-%d')
        DAYS=$(( (TODAY - $(date -d "$ts" +%s)) / 86400 ))
        printf "%-15s %-10s %-12s %-4d %s\n" "$pkg" "$version" "$HELD_SINCE" "$DAYS" "$reason"
        TOTAL=$((TOTAL+1))
        [ "$DAYS" -gt 14 ] && OLD=$((OLD+1))
    done < <(grep -v '^#' "$LOG_FILE" 2>/dev/null || true)

    echo
    echo "Total holds: $TOTAL"
    echo "Holds older than 14 days: $OLD"
}

release_hold() {
    PACKAGE="$2"
    if [ -z "$PACKAGE" ]; then
        echo "Specify a package to release: $0 release <package>"
        exit 1
    fi
    echo "Releasing hold on $PACKAGE..."
    sudo apt-mark unhold "$PACKAGE" && echo "  apt-mark unhold $PACKAGE: Done"

    # Remove from log
    if [ -f "$LOG_FILE" ]; then
        sudo sed -i "/| $PACKAGE |/d" "$LOG_FILE" && echo "  Removed from $LOG_FILE"
    fi

    echo
    echo "Package will be upgraded on next automatic cycle."
}

case "$COMMAND" in
    list)
        list_holds
        ;;
    release)
        release_hold "$@"
        ;;
    *)
        echo "Invalid command: $COMMAND"
        echo "Usage: $0 <list|release> [package]"
        exit 1
        ;;
esac
