#!/bin/bash

# Ecrit un fichier de policy firewall declarative.
# Les ports ouverts dependent de la configuration (SSH, HTTP, HTTPS).
write_firewall_policy() {
    ensure_parent_dir "$FIREWALL_POLICY_FILE" || return 1

    {
        printf 'DEFAULT_INPUT=deny\n'
        printf 'DEFAULT_OUTPUT=allow\n'
        printf 'ALLOW_TCP=%s\n' "$SSH_PORT"

        if [ "$ALLOW_HTTP" = "true" ]; then
            printf 'ALLOW_TCP=80\n'
        fi

        if [ "$ALLOW_HTTPS" = "true" ]; then
            printf 'ALLOW_TCP=443\n'
        fi
    } > "$FIREWALL_POLICY_FILE" \
        && log "INFO" "Firewall policy written to ${FIREWALL_POLICY_FILE}" \
        || {
            log "ERROR" "Failed to write firewall policy to ${FIREWALL_POLICY_FILE}"
            return 1
        }

    REPORT_FIREWALL_FILE="$FIREWALL_POLICY_FILE"
    REPORT_FIREWALL_PORTS="$SSH_PORT"

    if [ "$ALLOW_HTTP" = "true" ]; then
        REPORT_FIREWALL_PORTS="$(append_csv_value "$REPORT_FIREWALL_PORTS" "80")"
    fi

    if [ "$ALLOW_HTTPS" = "true" ]; then
        REPORT_FIREWALL_PORTS="$(append_csv_value "$REPORT_FIREWALL_PORTS" "443")"
    fi
}

# Applique des reglages reseau kernel dans sysctl.conf.
harden_kernel() {
    ensure_file_exists "$SYSCTL_CONF_FILE" || return 1

    set_equals_directive "$SYSCTL_CONF_FILE" "net.ipv4.ip_forward" "0" || return 1
    set_equals_directive "$SYSCTL_CONF_FILE" "net.ipv4.icmp_echo_ignore_all" "1" || return 1

    log "INFO" "Kernel hardening persisted in ${SYSCTL_CONF_FILE}"
}

# Orchestration du hardening reseau.
harden_network() {
    log "INFO" "Starting network hardening"

    write_firewall_policy || return 1
    harden_kernel || return 1

    log "INFO" "Network hardening completed successfully"
}