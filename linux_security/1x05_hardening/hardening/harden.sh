#!/bin/bash 

# Script principal du framework de hardening.
# Il charge la configuration, les modules, puis lance chaque etape.

set -eu

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_FILE="${BASE_DIR}/config/harden.cfg"

# Verifie que le fichier de configuration existe.
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: missing configuration file: $CONFIG_FILE" >&2
    exit 1
fi

# shellcheck source=/dev/null
. "$CONFIG_FILE"

# shellcheck source=/dev/null
. "${BASE_DIR}/lib/system.sh"
# shellcheck source=/dev/null
. "${BASE_DIR}/lib/network.sh"
# shellcheck source=/dev/null
. "${BASE_DIR}/lib/ssh.sh"
# shellcheck source=/dev/null
. "${BASE_DIR}/lib/identity.sh"

AUDIT_REPORT_FILE="${BASE_DIR}/audit_report.txt"

# Initialise l'etat global, le log et le rapport d'audit.
initialize_runtime_state
ensure_log_file
initialize_audit_report "$AUDIT_REPORT_FILE"

log "INFO" "Hardening framework initialized"
require_root

# Lance les etapes de hardening dans l'ordre.
# En cas d'echec d'une etape, le script genere le rapport puis s'arrete.
audit_info "Hardening procedure started."
log "INFO" "Beginning hardening run"

if ! harden_system; then
    audit_error "System hardening failed."
    finalize_audit_report
    exit 1
fi

if ! harden_network; then
    audit_error "Network hardening failed."
    finalize_audit_report
    exit 1
fi

if ! harden_ssh; then
    audit_error "SSH hardening failed."
    finalize_audit_report
    exit 1
fi

if ! harden_identity; then
    audit_error "Identity hardening failed."
    finalize_audit_report
    exit 1
fi

audit_info "Hardening procedure completed successfully."
log "INFO" "Hardening run completed successfully"

# Finalise le rapport et affiche un resume.
finalize_audit_report
echo "Hardening complete. See ${LOG_FILE} and ${AUDIT_REPORT_FILE} for details."