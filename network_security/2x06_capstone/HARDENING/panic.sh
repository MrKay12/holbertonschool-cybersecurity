#!/usr/bin/env bash
set -Eeuo pipefail
CONFIG_FILE="${CONFIG_FILE:-/etc/logicorp/hardening.conf}"
[[ -r "$CONFIG_FILE" ]] && source "$CONFIG_FILE"
PANIC_DELAY_SECONDS="${PANIC_DELAY_SECONDS:-180}"
ROLLBACK_DIR="/var/backups/logicorp-hardening"
ROLLBACK_FILE="$ROLLBACK_DIR/nftables.rollback.nft"
PID_FILE="/run/logicorp-firewall-rollback.pid"
mkdir -p "$ROLLBACK_DIR"
if nft list ruleset > "$ROLLBACK_FILE" 2>/dev/null; then chmod 600 "$ROLLBACK_FILE"; else printf 'flush ruleset\n' > "$ROLLBACK_FILE"; fi
cancel_existing(){ if [[ -s "$PID_FILE" ]]; then local p; p="$(cat "$PID_FILE" 2>/dev/null || true)"; [[ "$p" =~ ^[0-9]+$ ]] && kill "$p" 2>/dev/null || true; rm -f "$PID_FILE"; fi; }
if [[ "${1:-}" == "--confirm" ]]; then cancel_existing; echo "Rollback annule."; exit 0; fi
cancel_existing
( sleep "$PANIC_DELAY_SECONDS"; nft -f "$ROLLBACK_FILE"; rm -f "$PID_FILE"; logger -t logicorp-panic "Pare-feu restaure automatiquement." ) >/dev/null 2>&1 &
echo "$!" > "$PID_FILE"; chmod 600 "$PID_FILE"
echo "Rollback arme pour ${PANIC_DELAY_SECONDS}s. Confirmer avec : $0 --confirm"
