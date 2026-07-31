#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

[[ $EUID -eq 0 ]] || { echo "Erreur : execution root requise." >&2; exit 1; }
CONFIG_FILE="${CONFIG_FILE:-/etc/logicorp/hardening.conf}"
[[ -r "$CONFIG_FILE" ]] || { echo "Erreur : configuration absente : $CONFIG_FILE" >&2; exit 1; }
# shellcheck source=/dev/null
source "$CONFIG_FILE"

if ! command -v wg >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y wireguard
fi

mkdir -p "$WG_DIR" "$WG_CLIENT_DIR" "$WG_DIR/peers"
chmod 700 "$WG_DIR" "$WG_CLIENT_DIR" "$WG_DIR/peers"

SERVER_PRIVATE="$WG_DIR/server.key"
SERVER_PUBLIC="$WG_DIR/server.pub"
if [[ ! -s "$SERVER_PRIVATE" ]]; then
    wg genkey | tee "$SERVER_PRIVATE" | wg pubkey > "$SERVER_PUBLIC"
elif [[ ! -s "$SERVER_PUBLIC" ]]; then
    wg pubkey < "$SERVER_PRIVATE" > "$SERVER_PUBLIC"
fi
chmod 600 "$SERVER_PRIVATE" "$SERVER_PUBLIC"

peer_routes() {
    case "$1" in
        admin) printf '%s, %s, %s, %s, %s' "$MGMT_NET" "$DMZ_NET" "$SERVER_NET" "$OFFICE_NET" "$FINANCE_NET" ;;
        finance) printf '%s/32' "$FTP_SERVER_IP" ;;
        support) printf '%s' "$MGMT_NET" ;;
        *) echo "Role VPN inconnu : $1" >&2; return 1 ;;
    esac
}

WG_CONF_TMP="$(mktemp)"
trap 'rm -f "$WG_CONF_TMP"' EXIT
cat > "$WG_CONF_TMP" <<EOF_WG
[Interface]
Address = ${VPN_GATEWAY_ADDRESS}
ListenPort = ${VPN_PORT}
PrivateKey = $(cat "$SERVER_PRIVATE")
SaveConfig = false
EOF_WG

for entry in "${VPN_PEERS[@]}"; do
    IFS='|' read -r name ip role <<< "$entry"
    [[ -n "$name" && -n "$ip" && -n "$role" ]] || { echo "Pair VPN invalide : $entry" >&2; exit 1; }

    PEER_DIR="$WG_DIR/peers/$name"
    mkdir -p "$PEER_DIR"
    chmod 700 "$PEER_DIR"

    if [[ ! -s "$PEER_DIR/private.key" ]]; then
        wg genkey | tee "$PEER_DIR/private.key" | wg pubkey > "$PEER_DIR/public.key"
    elif [[ ! -s "$PEER_DIR/public.key" ]]; then
        wg pubkey < "$PEER_DIR/private.key" > "$PEER_DIR/public.key"
    fi
    chmod 600 "$PEER_DIR/private.key" "$PEER_DIR/public.key"

    cat >> "$WG_CONF_TMP" <<EOF_WG

[Peer]
# ${name} (${role})
PublicKey = $(cat "$PEER_DIR/public.key")
AllowedIPs = ${ip}/32
EOF_WG

    CLIENT_TMP="$(mktemp)"
    cat > "$CLIENT_TMP" <<EOF_CLIENT
[Interface]
Address = ${ip}/32
PrivateKey = $(cat "$PEER_DIR/private.key")
DNS = ${VPN_DNS}

[Peer]
PublicKey = $(cat "$SERVER_PUBLIC")
Endpoint = ${VPN_ENDPOINT}:${VPN_PORT}
AllowedIPs = $(peer_routes "$role")
PersistentKeepalive = 25
EOF_CLIENT
    install -m 600 "$CLIENT_TMP" "$WG_CLIENT_DIR/${name}.conf"
    rm -f "$CLIENT_TMP"
done

install -m 600 "$WG_CONF_TMP" "$WG_DIR/${VPN_IF}.conf"

sysctl -w net.ipv4.ip_forward=1 >/dev/null
systemctl enable "wg-quick@${VPN_IF}" >/dev/null
if systemctl is-active --quiet "wg-quick@${VPN_IF}"; then
    wg syncconf "$VPN_IF" <(wg-quick strip "$VPN_IF")
else
    systemctl start "wg-quick@${VPN_IF}"
fi

wg show "$VPN_IF"
echo "WireGuard configure de maniere idempotente."
echo "Configurations clientes : $WG_CLIENT_DIR"
