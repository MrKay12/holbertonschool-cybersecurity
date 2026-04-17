#!/bin/bash

set -euo pipefail

CONFIG_FILE="./sentinel.conf"

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Error: Configuration file '$CONFIG_FILE' not found." >&2
    exit 1
fi

source "$CONFIG_FILE"

if [[ -z "${SERVICES+x}" ]]; then
    echo "Error: SERVICES variable is not defined in config." >&2
    exit 1
fi

if [[ -z "${FILES_TO_WATCH+x}" ]]; then
    echo "Error: FILES_TO_WATCH variable is not defined in config." >&2
    exit 1
fi

if [[ ${#SERVICES[@]} -eq 0 ]]; then
    echo "Error: SERVICES array is empty." >&2
    exit 1
fi

if [[ ${#FILES_TO_WATCH[@]} -eq 0 ]]; then
    echo "Error: FILES_TO_WATCH array is empty." >&2
    exit 1
fi

echo "Configuration loaded successfully."
echo "Services: ${SERVICES[*]}"
echo "Files to watch: ${FILES_TO_WATCH[*]}"

check_services() {
    local svc

    for svc in "${SERVICES[@]}"; do
        if pgrep -f "$svc" > /dev/null 2>&1; then
            echo "OK: $svc is running"
        else
            if eval "$svc" > /dev/null 2>&1; then
                echo "FIXED: Restarted $svc"
            else
                echo "ERROR: Failed to restart $svc" >&2
            fi
        fi
    done
}

check_integrity() {
    local file gold live_hash gold_hash base

    for file in "${FILES_TO_WATCH[@]}"; do
        base="$(basename "$file")"
        gold="/var/backups/sentinel/${base}.gold"

        if [[ ! -f "$file" ]]; then
            echo "ERROR: Live file missing: $file" >&2
            continue
        fi

        if [[ ! -f "$gold" ]]; then
            echo "ERROR: Golden copy missing: $gold" >&2
            continue
        fi

        live_hash="$(md5sum "$file" | awk '{print $1}')"
        gold_hash="$(md5sum "$gold" | awk '{print $1}')"

        if [[ "$live_hash" == "$gold_hash" ]]; then
            echo "OK: $file integrity verified"
        else
            if cp "$gold" "$file"; then
                echo "FIXED: Restored $file"
            else
                echo "ERROR: Failed to restore $file" >&2
            fi
        fi
    done
}

check_ports() {
    local port pid

    while read -r port pid; do
        [[ -z "$port" ]] && continue

        # Check if port is allowed
        if [[ " ${ALLOWED_PORTS[*]} " =~ " ${port} " ]]; then
            continue
        fi

        if kill -9 "$pid" > /dev/null 2>&1; then
            echo "ALERT: Killed rogue process on port $port"
        else
            echo "ERROR: Failed to kill process on port $port" >&2
        fi

    done < <(
        ss -tlnp 2>/dev/null | awk '
            NR>1 {
                split($4, a, ":")
                port=a[length(a)]
                if ($NF ~ /pid=/) {
                    match($NF, /pid=([0-9]+)/, m)
                    if (m[1] != "") {
                        print port, m[1]
                    }
                }
            }
        '
    )
}

if [[ -z "${ALLOWED_PORTS+x}" ]]; then
    echo "Error: ALLOWED_PORTS is not defined." >&2
    exit 1
fi