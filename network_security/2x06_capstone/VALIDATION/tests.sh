#!/usr/bin/env bash
# Automated security compliance checks for the LogiCorp bastion.
# All environment-specific values are loaded from hardening.conf.

set -uo pipefail

CONFIG_FILE="${CONFIG_FILE:-/etc/logicorp/hardening.conf}"
PASS_COUNT=0
FAIL_COUNT=0
TOTAL_COUNT=0

pass() {
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    PASS_COUNT=$((PASS_COUNT + 1))
    printf '[PASS] %s\n' "$1"
}

fail() {
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    FAIL_COUNT=$((FAIL_COUNT + 1))
    printf '[FAIL] %s\n' "$1"
}

check() {
    local description="$1"
    shift

    if "$@" >/dev/null 2>&1; then
        pass "$description"
    else
        fail "$description"
    fi
}

require_command() {
    command -v "$1" >/dev/null 2>&1
}

config_is_loaded() {
    [[ -r "$CONFIG_FILE" ]]
}

service_is_active() {
    systemctl is-active --quiet "$1"
}

service_is_stopped() {
    ! systemctl is-active --quiet "$1"
}

interface_is_up() {
    ip link show dev "$1" 2>/dev/null | grep -q 'state UP'
}

interface_has_address() {
    local interface="$1"
    local address="$2"

    ip -o address show dev "$interface" 2>/dev/null |
        awk '{print $4}' |
        grep -Fxq "$address"
}

route_uses_interface() {
    local network="$1"
    local interface="$2"

    ip route show "$network" 2>/dev/null |
        grep -Eq "(^|[[:space:]])dev[[:space:]]+${interface}([[:space:]]|$)"
}

chain_policy_is_drop() {
    local family="$1"
    local table="$2"
    local chain="$3"

    nft list chain "$family" "$table" "$chain" 2>/dev/null |
        grep -Eq 'policy[[:space:]]+drop[[:space:]]*;'
}

nft_rule_exists() {
    local chain="$1"
    local expression="$2"

    nft -a list chain inet filter "$chain" 2>/dev/null |
        grep -Fq -- "$expression"
}

ssh_effective_value_is() {
    local option="$1"
    local expected="$2"
    local actual

    actual="$(sshd -T 2>/dev/null | awk -v key="$option" '$1 == key {print $2; exit}')"
    [[ "$actual" == "$expected" ]]
}

wireguard_listens_on_expected_port() {
    wg show "$VPN_IF" listen-port 2>/dev/null | grep -Fxq "$VPN_PORT"
}

wireguard_has_expected_address() {
    interface_has_address "$VPN_IF" "$VPN_GATEWAY_ADDR"
}

wireguard_has_all_configured_peers() {
    local peer name public_key

    for peer in $ADMIN_PEERS $FINANCE_PEERS; do
        name="${peer%%:*}"
        [[ -s "$WG_DIR/peers/$name/public.key" ]] || return 1
        public_key="$(cat "$WG_DIR/peers/$name/public.key")"
        wg show "$VPN_IF" peers 2>/dev/null | grep -Fxq "$public_key" || return 1
    done
}

udp_port_is_listening() {
    local port="$1"

    ss -H -lun 2>/dev/null |
        awk '{print $5}' |
        grep -Eq "(^|:)${port}$"
}

user_has_sudo_access() {
    local user="$1"

    id "$user" >/dev/null 2>&1 || return 1
    sudo -l -U "$user" 2>/dev/null | grep -Eq 'may run the following commands|ALL'
}

all_expected_users_have_sudo() {
    local user

    [[ -n "${SUDO_ALLOWED_USERS:-}" ]] || return 1
    for user in $SUDO_ALLOWED_USERS; do
        user_has_sudo_access "$user" || return 1
    done
}

no_unexpected_sudo_group_members() {
    local actual expected user group

    expected=" $(printf '%s ' ${SUDO_ALLOWED_USERS:-})"
    for group in sudo wheel; do
        getent group "$group" >/dev/null 2>&1 || continue
        actual="$(getent group "$group" | awk -F: '{print $4}' | tr ',' ' ')"
        for user in $actual; do
            [[ "$expected" == *" $user "* ]] || return 1
        done
    done
}

ip_forwarding_is_enabled() {
    [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" == "1" ]]
}

expected_interface_variables_exist() {
    local variable
    for variable in \
        WAN_IF OFFICE_IF OFFICE_ADDR FINANCE_IF FINANCE_ADDR \
        DMZ_IF DMZ_ADDR SERVER_IF SERVER_ADDR GUEST_IF GUEST_ADDR \
        MGMT_IF MGMT_ADDR VPN_IF VPN_GATEWAY_ADDR; do
        [[ -n "${!variable:-}" ]] || return 1
    done
}

all_expected_interfaces_are_up() {
    local interface
    for interface in \
        "$WAN_IF" "$OFFICE_IF" "$FINANCE_IF" "$DMZ_IF" \
        "$SERVER_IF" "$GUEST_IF" "$MGMT_IF" "$VPN_IF"; do
        interface_is_up "$interface" || return 1
    done
}

all_expected_addresses_are_configured() {
    interface_has_address "$OFFICE_IF" "$OFFICE_ADDR" &&
    interface_has_address "$FINANCE_IF" "$FINANCE_ADDR" &&
    interface_has_address "$DMZ_IF" "$DMZ_ADDR" &&
    interface_has_address "$SERVER_IF" "$SERVER_ADDR" &&
    interface_has_address "$GUEST_IF" "$GUEST_ADDR" &&
    interface_has_address "$MGMT_IF" "$MGMT_ADDR" &&
    interface_has_address "$VPN_IF" "$VPN_GATEWAY_ADDR"
}

all_connected_routes_are_correct() {
    route_uses_interface "$OFFICE_NET" "$OFFICE_IF" &&
    route_uses_interface "$FINANCE_NET" "$FINANCE_IF" &&
    route_uses_interface "$DMZ_NET" "$DMZ_IF" &&
    route_uses_interface "$SERVER_NET" "$SERVER_IF" &&
    route_uses_interface "$GUEST_NET" "$GUEST_IF" &&
    route_uses_interface "$MGMT_NET" "$MGMT_IF" &&
    route_uses_interface "$VPN_NET" "$VPN_IF"
}

default_route_uses_wan() {
    ip route show default 2>/dev/null |
        grep -Eq "(^|[[:space:]])dev[[:space:]]+${WAN_IF}([[:space:]]|$)"
}

normalize_accept_rules() {
    sed -E \
        -e 's/[[:space:]]+# handle [0-9]+//g' \
        -e 's/counter packets [0-9]+ bytes [0-9]+[[:space:]]*//g' \
        -e 's/[[:space:]]+/ /g' \
        -e 's/^ //; s/ $//' |
        grep -E '(^|[[:space:]])accept([[:space:]]|$)' |
        sort -u
}

no_unexpected_accept_rules() {
    local live_file expected_file
    live_file="$(mktemp)"
    expected_file="$(mktemp)"

    nft -a list table inet filter 2>/dev/null |
        normalize_accept_rules > "$live_file"

    # The deployed nftables configuration is the approved source of truth.
    normalize_accept_rules < "$NFT_CONF" > "$expected_file"

    if [[ ! -s "$live_file" || ! -s "$expected_file" ]]; then
        rm -f "$live_file" "$expected_file"
        return 1
    fi

    if comm -23 "$live_file" "$expected_file" | grep -q .; then
        rm -f "$live_file" "$expected_file"
        return 1
    fi

    rm -f "$live_file" "$expected_file"
    return 0
}

required_firewall_rules_exist() {
    nft_rule_exists input "udp dport $VPN_PORT accept" &&
    nft_rule_exists input "tcp dport $SSH_PORT accept" &&
    nft_rule_exists forward "ip daddr $FTP_SERVER_IP" &&
    nft_rule_exists forward "tcp dport { $FTP_CONTROL_PORT, $FTP_PASSIVE_MIN-$FTP_PASSIVE_MAX } accept" &&
    nft_rule_exists forward "ip daddr $DATABASE_IP tcp dport $DATABASE_PORT accept" &&
    nft list chain ip nat postrouting 2>/dev/null | grep -q 'masquerade'
}

ftp_is_restricted_to_finance() {
    local chain
    chain="$(nft -a list chain inet filter forward 2>/dev/null)"

    grep -Fq "iifname \"$FINANCE_IF\" ip daddr $FTP_SERVER_IP" <<< "$chain" &&
    grep -Fq "iifname \"$VPN_IF\" ip saddr @finance_vpn_peers ip daddr $FTP_SERVER_IP" <<< "$chain" &&
    ! grep -E "iifname \"(${OFFICE_IF}|${GUEST_IF})\".*ip daddr ${FTP_SERVER_IP}.*accept" <<< "$chain" >/dev/null
}

print_header() {
    printf '%s\n' 'LogiCorp Bastion Compliance Check'
    printf 'Configuration: %s\n\n' "$CONFIG_FILE"
}

print_result() {
    printf '\nRESULT: %d/%d checks passed\n' "$PASS_COUNT" "$TOTAL_COUNT"
    [[ "$FAIL_COUNT" -eq 0 ]]
}

print_header

if ! config_is_loaded; then
    fail "Configuration file '$CONFIG_FILE' is readable"
    print_result
    exit 1
fi

# shellcheck disable=SC1090
source "$CONFIG_FILE"

check "Script is running with root privileges" test "$EUID" -eq 0
check "nft command is available" require_command nft
check "sshd command is available" require_command sshd
check "wg command is available" require_command wg
check "ip command is available" require_command ip
check "ss command is available" require_command ss

check "Firewall service is running" service_is_active nftables
check "Firewall default INPUT policy is DROP" chain_policy_is_drop inet filter input
check "Firewall default FORWARD policy is DROP" chain_policy_is_drop inet filter forward
check "Required firewall rules exist" required_firewall_rules_exist
check "No unexpected ACCEPT rules are active" no_unexpected_accept_rules
check "FTP is restricted to Finance networks" ftp_is_restricted_to_finance
check "NAT masquerading is configured" bash -c 'nft list chain ip nat postrouting 2>/dev/null | grep -q masquerade'

check "SSH service is running" service_is_active ssh
check "SSH configuration syntax is valid" sshd -t
check "SSH root login is disabled" ssh_effective_value_is permitrootlogin no
check "SSH password authentication is disabled" ssh_effective_value_is passwordauthentication no
check "SSH keyboard-interactive authentication is disabled" ssh_effective_value_is kbdinteractiveauthentication no
check "SSH public-key authentication is enabled" ssh_effective_value_is pubkeyauthentication yes
check "SSH empty passwords are disabled" ssh_effective_value_is permitemptypasswords no

check "VPN service wg-quick@$VPN_IF is running" service_is_active "wg-quick@$VPN_IF"
check "VPN interface $VPN_IF is UP" interface_is_up "$VPN_IF"
check "VPN interface has address $VPN_GATEWAY_ADDR" wireguard_has_expected_address
check "WireGuard listens on configured port $VPN_PORT" wireguard_listens_on_expected_port
check "WireGuard UDP port $VPN_PORT is listening" udp_port_is_listening "$VPN_PORT"
check "All configured WireGuard peers are loaded" wireguard_has_all_configured_peers

for service in $DISABLED_SERVICES; do
    check "Unexpected service '$service' is stopped" service_is_stopped "$service"
done

check "All configured sudo users have sudo access" all_expected_users_have_sudo
check "No unexpected users belong to sudo administrator groups" no_unexpected_sudo_group_members

check "IPv4 forwarding is enabled" ip_forwarding_is_enabled
check "Expected interface address variables are configured" expected_interface_variables_exist

if expected_interface_variables_exist; then
    check "All expected network interfaces are UP" all_expected_interfaces_are_up
    check "Interfaces have the configured IP addresses" all_expected_addresses_are_configured
    check "Connected network routes use the correct interfaces" all_connected_routes_are_correct
else
    fail "All expected network interfaces are UP"
    fail "Interfaces have the configured IP addresses"
    fail "Connected network routes use the correct interfaces"
fi

check "Default route uses WAN interface $WAN_IF" default_route_uses_wan

print_result
