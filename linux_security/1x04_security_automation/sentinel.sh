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

if [[ -z "${ALLOWED_PORTS+x}" ]]; then
    echo "Error: ALLOWED_PORTS is not defined." >&2
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

log() {
    local component="$1"
    local target="$2"
    local status="$3"
    local details="$4"
    local timestamp

    timestamp="$(date -u +%FT%TZ)"

    printf '{"timestamp":"%s","component":"%s","target":"%s","status":"%s","details":"%s"}\n' \
        "$timestamp" "$component" "$target" "$status" "$details" >> /var/log/sentinel.log
}

echo "Configuration loaded successfully."
echo "Services: ${SERVICES[*]}"
echo "Files to watch: ${FILES_TO_WATCH[*]}"

check_services() {
    local svc

    for svc in "${SERVICES[@]}"; do
        if pgrep -f "$svc" > /dev/null 2>&1; then
            echo "OK: $svc is running"
            log "SERVICE" "$svc" "OK" "Service is running"
        else
            if eval "$svc" > /dev/null 2>&1; then
                echo "FIXED: Restarted $svc"
                log "SERVICE" "$svc" "FIXED" "Restarted service"
            else
                echo "ALERT: Failed to restart $svc" >&2
                log "SERVICE" "$svc" "ALERT" "Failed to restart service"
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
            echo "ALERT: Live file missing: $file" >&2
            log "INTEGRITY" "$file" "ALERT" "Live file missing"
            continue
        fi

        if [[ ! -f "$gold" ]]; then
            echo "ALERT: Golden copy missing: $gold" >&2
            log "INTEGRITY" "$file" "ALERT" "Golden copy missing"
            continue
        fi

        live_hash="$(md5sum "$file" | awk '{print $1}')"
        gold_hash="$(md5sum "$gold" | awk '{print $1}')"

        if [[ "$live_hash" == "$gold_hash" ]]; then
            echo "OK: $file integrity verified"
            log "INTEGRITY" "$file" "OK" "Integrity verified"
        else
            if cp "$gold" "$file"; then
                echo "FIXED: Restored $file"
                log "INTEGRITY" "$file" "FIXED" "Restored file from golden copy"
            else
                echo "ALERT: Failed to restore $file" >&2
                log "INTEGRITY" "$file" "ALERT" "Failed to restore file from golden copy"
            fi
        fi
    done
}

check_ports() {
    local port pid allowed is_allowed

    while read -r port pid; do
        [[ -z "$port" ]] && continue

        is_allowed=false

        for allowed in "${ALLOWED_PORTS[@]}"; do
            if [[ "$port" == "$allowed" ]]; then
                is_allowed=true
                break
            fi
        done

        if [[ "$is_allowed" == true ]]; then
            continue
        fi

        if kill -9 "$pid" > /dev/null 2>&1; then
            echo "ALERT: Killed rogue process on port $port"
            log "PORT" "$port" "ALERT" "Killed rogue process on unauthorized port"
        else
            echo "ALERT: Failed to kill process on port $port" >&2
            log "PORT" "$port" "ALERT" "Failed to kill rogue process on unauthorized port"
        fi

    done < <(
        ss -tlnp 2>/dev/null | awk '
            NR > 1 {
                split($4, a, ":")
                port = a[length(a)]
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

check_services
check_integrity
check_ports