#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "Execution root requise." >&2; exit 1; }
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p /etc/logicorp
install -m 600 "$SRC/hardening.conf" /etc/logicorp/hardening.conf
install -m 750 "$SRC/panic.sh" /usr/local/sbin/panic.sh
install -m 750 "$SRC/clean.sh" /usr/local/sbin/logicorp-clean
install -m 750 "$SRC/vpn_setup.sh" /usr/local/sbin/logicorp-vpn-setup
install -m 750 "$SRC/firewall.sh" /usr/local/sbin/logicorp-firewall
echo "Installation terminee. Modifier /etc/logicorp/hardening.conf avant execution."
