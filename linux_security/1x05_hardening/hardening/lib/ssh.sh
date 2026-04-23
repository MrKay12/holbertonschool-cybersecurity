#!/bin/bash

# Durcit la configuration SSH:
# - met a jour les directives principales
# - valide la configuration si sshd est disponible
harden_ssh() {
    log "INFO" "Starting SSH hardening"

    if [ ! -f "$SSH_CONFIG_FILE" ]; then
        log "ERROR" "SSH config file not found: ${SSH_CONFIG_FILE}"
        return 1
    fi

    backup_file_once "$SSH_CONFIG_FILE" || return 1

    set_space_directive "$SSH_CONFIG_FILE" "Port" "$SSH_PORT" || return 1
    set_space_directive "$SSH_CONFIG_FILE" "PasswordAuthentication" "$PASSWORD_AUTHENTICATION" || return 1
    set_space_directive "$SSH_CONFIG_FILE" "PubkeyAuthentication" "$PUBKEY_AUTHENTICATION" || return 1
    set_space_directive "$SSH_CONFIG_FILE" "PermitRootLogin" "$PERMIT_ROOT_LOGIN" || return 1

    if command -v sshd >/dev/null 2>&1; then
        if sshd -t -f "$SSH_CONFIG_FILE" >/dev/null 2>&1; then
            log "INFO" "SSH configuration validation succeeded"
        else
            log "ERROR" "SSH configuration validation failed"
            return 1
        fi
    else
        log "INFO" "sshd command not found, skipping SSH config validation"
    fi

    REPORT_SSH_PORT="$SSH_PORT"

    log "INFO" "SSH hardening completed successfully"
}