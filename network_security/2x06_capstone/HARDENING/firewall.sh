#!/usr/bin/env bash
set -Eeuo pipefail

[[ $EUID -eq 0 ]] || { echo "Erreur : execution root requise." >&2; exit 1; }

CONFIG_FILE="${CONFIG_FILE:-/etc/logicorp/hardening.conf}"
[[ -r "$CONFIG_FILE" ]] || { echo "Erreur : configuration absente : $CONFIG_FILE" >&2; exit 1; }
# shellcheck source=/dev/null
source "$CONFIG_FILE"

command -v nft >/dev/null 2>&1 || { echo "Erreur : nftables absent." >&2; exit 1; }
[[ -x "$PANIC_SCRIPT" ]] || { echo "Erreur : panic.sh absent ou non executable." >&2; exit 1; }

required_vars=(WAN_IF OFFICE_IF FINANCE_IF DMZ_IF SERVER_IF GUEST_IF MGMT_IF VPN_IF \
OFFICE_NET FINANCE_NET DMZ_NET SERVER_NET GUEST_NET MGMT_NET VPN_NET \
FTP_SERVER_IP FTP_CONTROL_PORT FTP_PASSIVE_MIN FTP_PASSIVE_MAX DATABASE_IP DATABASE_PORT \
VPN_PORT SSH_PORT NFT_CONF)
for var in "${required_vars[@]}"; do
    [[ -n "${!var:-}" ]] || { echo "Erreur : variable vide : $var" >&2; exit 1; }
done

join_comma() {
    local out="" item
    for item in "$@"; do
        [[ -n "$out" ]] && out+=", "
        out+="$item"
    done
    printf '%s' "$out"
}

peer_ips_by_role() {
    local wanted="$1" entry name ip role
    local result=()
    for entry in "${VPN_PEERS[@]}"; do
        IFS='|' read -r name ip role <<< "$entry"
        [[ "$role" == "$wanted" ]] && result+=("$ip")
    done
    join_comma "${result[@]}"
}

nft_ports() {
    local -n ports_ref=$1
    join_comma "${ports_ref[@]}"
}

ADMIN_VPN_IPS="$(peer_ips_by_role admin)"
FINANCE_VPN_IPS="$(peer_ips_by_role finance)"
APP_SERVER_SET="$(join_comma "${APP_SERVER_IPS[@]}")"
PRIVATE_NET_SET="$(join_comma "${PRIVATE_NETS[@]}")"
NAT_NET_SET="$(join_comma "$OFFICE_NET" "$FINANCE_NET" "$DMZ_NET" "$SERVER_NET" "$GUEST_NET" "$MGMT_NET" "$VPN_NET")"

[[ -n "$ADMIN_VPN_IPS" ]] || { echo "Erreur : aucun pair VPN admin configure." >&2; exit 1; }
[[ -n "$FINANCE_VPN_IPS" ]] || { echo "Erreur : aucun pair VPN finance configure." >&2; exit 1; }
[[ -n "$APP_SERVER_SET" ]] || { echo "Erreur : aucun serveur applicatif configure." >&2; exit 1; }

TMP_RULESET="$(mktemp)"
trap 'rm -f "$TMP_RULESET"' EXIT

cat > "$TMP_RULESET" <<EOF_RULESET
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    set private_nets {
        type ipv4_addr
        flags interval
        elements = { ${PRIVATE_NET_SET} }
    }

    set admin_vpn_peers {
        type ipv4_addr
        elements = { ${ADMIN_VPN_IPS} }
    }

    set finance_vpn_peers {
        type ipv4_addr
        elements = { ${FINANCE_VPN_IPS} }
    }

    set app_servers {
        type ipv4_addr
        elements = { ${APP_SERVER_SET} }
    }

    chain input {
        type filter hook input priority 0;
        policy drop;

        ct state invalid drop
        ct state established,related accept
        iifname "lo" accept
        ip protocol icmp limit rate 10/second accept
        ip6 nexthdr ipv6-icmp limit rate 10/second accept

        iifname "${WAN_IF}" udp dport ${VPN_PORT} accept
        iifname "${MGMT_IF}" tcp dport ${SSH_PORT} accept
        iifname "${VPN_IF}" ip saddr @admin_vpn_peers tcp dport ${SSH_PORT} accept

        limit rate 10/second burst 20 packets log prefix "NFT-INPUT-DROP " flags all counter
    }

    chain forward {
        type filter hook forward priority 0;
        policy drop;

        ct state invalid drop
        ct state established,related accept

        iifname "${FINANCE_IF}" ip daddr ${FTP_SERVER_IP} tcp dport { ${FTP_CONTROL_PORT}, ${FTP_PASSIVE_MIN}-${FTP_PASSIVE_MAX} } accept
        iifname "${VPN_IF}" ip saddr @finance_vpn_peers ip daddr ${FTP_SERVER_IP} tcp dport { ${FTP_CONTROL_PORT}, ${FTP_PASSIVE_MIN}-${FTP_PASSIVE_MAX} } accept

        iifname "${VPN_IF}" ip saddr @admin_vpn_peers oifname { "${OFFICE_IF}", "${FINANCE_IF}", "${DMZ_IF}", "${SERVER_IF}", "${MGMT_IF}" } accept
        iifname "${MGMT_IF}" oifname { "${OFFICE_IF}", "${FINANCE_IF}", "${DMZ_IF}", "${SERVER_IF}" } accept

        ip saddr @app_servers ip daddr ${DATABASE_IP} tcp dport ${DATABASE_PORT} accept

        iifname "${GUEST_IF}" ip daddr @private_nets drop
EOF_RULESET

append_outbound_rules() {
    local iface="$1" tcp_name="$2" udp_name="$3"
    local tcp_ports udp_ports
    tcp_ports="$(nft_ports "$tcp_name")"
    udp_ports="$(nft_ports "$udp_name")"

    [[ -z "$tcp_ports" ]] || printf '        iifname "%s" oifname "%s" tcp dport { %s } accept\n' "$iface" "$WAN_IF" "$tcp_ports" >> "$TMP_RULESET"
    [[ -z "$udp_ports" ]] || printf '        iifname "%s" oifname "%s" udp dport { %s } accept\n' "$iface" "$WAN_IF" "$udp_ports" >> "$TMP_RULESET"
}

append_outbound_rules "$GUEST_IF" GUEST_TCP_OUT GUEST_UDP_OUT
append_outbound_rules "$OFFICE_IF" OFFICE_TCP_OUT OFFICE_UDP_OUT
append_outbound_rules "$FINANCE_IF" FINANCE_TCP_OUT FINANCE_UDP_OUT
append_outbound_rules "$DMZ_IF" DMZ_TCP_OUT DMZ_UDP_OUT
append_outbound_rules "$SERVER_IF" SERVER_TCP_OUT SERVER_UDP_OUT

cat >> "$TMP_RULESET" <<EOF_RULESET
        limit rate 10/second burst 20 packets log prefix "NFT-FORWARD-DROP " flags all counter
    }
}

table ip nat {
    chain postrouting {
        type nat hook postrouting priority srcnat;
        oifname "${WAN_IF}" ip saddr { ${NAT_NET_SET} } masquerade
    }
}
EOF_RULESET

nft -c -f "$TMP_RULESET"

# Le rollback est obligatoirement arme avant la modification du ruleset.
"$PANIC_SCRIPT"

install -m 600 "$TMP_RULESET" "$NFT_CONF"
nft -f "$NFT_CONF"
systemctl enable nftables >/dev/null 2>&1 || true

# Verifie que le ruleset charge correspond au fichier genere.
nft list ruleset >/dev/null

echo "Pare-feu applique avec succes."
echo "Testez SSH, WireGuard, FTP Finance et la base de donnees."
echo "Puis confirmez : $PANIC_SCRIPT --confirm"
