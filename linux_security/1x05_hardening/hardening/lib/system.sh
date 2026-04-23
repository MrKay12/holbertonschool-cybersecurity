#!/bin/bash

# Ecrit un message horodate dans le fichier de log.
log() {
    local level="$1"
    shift
    local message="$*"

    printf '%s [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$message" >> "$LOG_FILE"
}

# Verifie que le script est execute en root.
require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log "ERROR" "Script must be run as root"
        audit_error "Script must be run as root."
        finalize_audit_report
        echo "Error: script must be run as root." >&2
        exit 1
    fi
}

# Cree le fichier de log si necessaire.
ensure_log_file() {
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE" 2>/dev/null || {
        echo "Error: unable to write to log file: $LOG_FILE" >&2
        exit 1
    }
}

# Cree le dossier parent d'un chemin cible.
ensure_parent_dir() {
    local target_path="$1"

    mkdir -p "$(dirname "$target_path")" \
        && log "INFO" "Ensured parent directory for ${target_path}" \
        || {
            log "ERROR" "Failed to ensure parent directory for ${target_path}"
            return 1
        }
}

# Cree une sauvegarde .bak une seule fois pour un fichier.
backup_file_once() {
    local target_file="$1"
    local backup_file="${target_file}.bak"

    if [ ! -f "$target_file" ]; then
        return 0
    fi

    if [ -f "$backup_file" ]; then
        log "INFO" "Backup already exists: ${backup_file}"
        return 0
    fi

    cp "$target_file" "$backup_file" \
        && log "INFO" "Backup created: ${backup_file}" \
        || {
            log "ERROR" "Failed to back up ${target_file}"
            return 1
        }
}

# Garantit qu'un fichier existe (creation du dossier parent si besoin).
ensure_file_exists() {
    local file="$1"

    ensure_parent_dir "$file" || return 1
    [ -f "$file" ] || touch "$file"

    if [ -f "$file" ]; then
        log "INFO" "Ensured file exists: ${file}"
    else
        log "ERROR" "Failed to ensure file exists: ${file}"
        return 1
    fi
}

# Defini une directive de type "cle valeur" dans un fichier.
# Si la cle existe deja, la premiere occurrence est remplacee.
set_space_directive() {
    local file="$1"
    local key="$2"
    local value="$3"
    local tmp_file

    ensure_file_exists "$file" || return 1
    tmp_file="$(mktemp)" || return 1

    awk -v key="$key" -v value="$value" '
        BEGIN { done=0 }
        {
            if ($0 ~ "^[[:space:]]*#?[[:space:]]*" key "[[:space:]]+") {
                if (done == 0) {
                    print key " " value
                    done=1
                }
            } else {
                print
            }
        }
        END {
            if (done == 0) {
                print key " " value
            }
        }
    ' "$file" > "$tmp_file" \
        && mv "$tmp_file" "$file" \
        && log "INFO" "Set directive ${key} in ${file} to '${value}'" \
        || {
            rm -f "$tmp_file"
            log "ERROR" "Failed to set directive ${key} in ${file}"
            return 1
        }
}

# Defini une directive de type "cle=valeur" dans un fichier.
# Si la cle existe deja, la premiere occurrence est remplacee.
set_equals_directive() {
    local file="$1"
    local key="$2"
    local value="$3"
    local tmp_file

    ensure_file_exists "$file" || return 1
    tmp_file="$(mktemp)" || return 1

    awk -v key="$key" -v value="$value" '
        BEGIN { done=0 }
        {
            if ($0 ~ "^[[:space:]]*#?[[:space:]]*" key "=") {
                if (done == 0) {
                    print key "=" value
                    done=1
                }
            } else {
                print
            }
        }
        END {
            if (done == 0) {
                print key "=" value
            }
        }
    ' "$file" > "$tmp_file" \
        && mv "$tmp_file" "$file" \
        && log "INFO" "Set directive ${key} in ${file} to '${value}'" \
        || {
            rm -f "$tmp_file"
            log "ERROR" "Failed to set directive ${key} in ${file}"
            return 1
        }
}

# Ajoute une ligne exacte si elle est absente.
ensure_exact_line() {
    local file="$1"
    local line="$2"

    ensure_file_exists "$file" || return 1

    if grep -Fqx "$line" "$file"; then
        log "INFO" "Line already present in ${file}: ${line}"
        return 0
    fi

    printf '%s\n' "$line" >> "$file" \
        && log "INFO" "Added line to ${file}: ${line}" \
        || {
            log "ERROR" "Failed to add line to ${file}: ${line}"
            return 1
        }
}

# Supprime toutes les lignes qui correspondent a une regex.
remove_matching_lines() {
    local file="$1"
    local regex="$2"
    local tmp_file

    ensure_file_exists "$file" || return 1
    tmp_file="$(mktemp)" || return 1

    awk -v regex="$regex" '
        $0 !~ regex { print }
    ' "$file" > "$tmp_file" \
        && mv "$tmp_file" "$file" \
        && log "INFO" "Removed matching lines from ${file} using regex: ${regex}" \
        || {
            rm -f "$tmp_file"
            log "ERROR" "Failed to remove matching lines from ${file}"
            return 1
        }
}

# Retourne succes si un paquet Debian est installe.
package_installed() {
    dpkg -s "$1" >/dev/null 2>&1
}

# Retourne succes si un groupe existe.
group_exists() {
    getent group "$1" >/dev/null 2>&1
}

# Retourne succes si un utilisateur appartient a un groupe.
user_in_group() {
    local user_name="$1"
    local group_name="$2"

    id -nG "$user_name" 2>/dev/null | tr ' ' '\n' | grep -Fxq "$group_name"
}

# Retourne succes si un utilisateur existe.
user_exists() {
    id "$1" >/dev/null 2>&1
}

# Initialise les variables de suivi pour l'audit.
initialize_runtime_state() {
    AUDIT_STATUS="PASS"
    AUDIT_LINES=""
    AUDIT_WARNINGS=""
    AUDIT_ERRORS=""

    REPORT_SSH_PORT=""
    REPORT_FIREWALL_PORTS=""
    REPORT_FIREWALL_FILE=""

    REPORT_INSTALLED_PACKAGES=""
    REPORT_ALREADY_INSTALLED_PACKAGES=""
    REPORT_REMOVED_PACKAGES=""
    REPORT_ALREADY_ABSENT_PACKAGES=""

    REPORT_REMOVED_USERS_COUNT="0"
    REPORT_REMOVED_USERS_LIST=""
}

# Ajoute une valeur a une liste CSV (separee par virgules).
append_csv_value() {
    local current_value="$1"
    local new_value="$2"

    if [ -z "$new_value" ]; then
        printf '%s' "$current_value"
        return
    fi

    if [ -z "$current_value" ]; then
        printf '%s' "$new_value"
    else
        printf '%s, %s' "$current_value" "$new_value"
    fi
}

# Ajoute une ligne au contenu du rapport d'audit en memoire.
audit_append_line() {
    local level="$1"
    shift
    local message="$*"

    AUDIT_LINES="${AUDIT_LINES}[${level}] ${message}
"
}

# Ajoute une ligne INFO au rapport d'audit.
audit_info() {
    audit_append_line "INFO" "$*"
}

# Ajoute un avertissement a l'audit et au log.
audit_warn() {
    AUDIT_STATUS="PASS"
    AUDIT_WARNINGS="${AUDIT_WARNINGS}[WARN] $*
"
    audit_append_line "WARN" "$*"
    log "WARN" "$*"
}

# Ajoute une erreur a l'audit et au log.
audit_error() {
    AUDIT_STATUS="FAIL"
    AUDIT_ERRORS="${AUDIT_ERRORS}[ERROR] $*
"
    audit_append_line "ERROR" "$*"
    log "ERROR" "$*"
}

# Cree/vider le fichier de rapport d'audit.
initialize_audit_report() {
    AUDIT_REPORT_FILE="$1"

    if [ -z "$AUDIT_REPORT_FILE" ]; then
        echo "Error: audit report path is empty." >&2
        exit 1
    fi

    : > "$AUDIT_REPORT_FILE" || {
        echo "Error: unable to initialize audit report: $AUDIT_REPORT_FILE" >&2
        exit 1
    }
}

# Ecrit les lignes de synthese (SSH, firewall, utilisateurs, paquets).
write_audit_summary_lines() {
    local removed_users_message
    local installed_message
    local removed_message

    if [ -n "$REPORT_SSH_PORT" ]; then
        audit_info "SSH configured on port ${REPORT_SSH_PORT}."
    fi

    if [ -n "$REPORT_FIREWALL_FILE" ] && [ -n "$REPORT_FIREWALL_PORTS" ]; then
        audit_info "Firewall policy created: ports ${REPORT_FIREWALL_PORTS} ALLOWED."
        audit_info "Firewall policy file: ${REPORT_FIREWALL_FILE}."
    fi

    if [ "$REPORT_REMOVED_USERS_COUNT" -gt 0 ]; then
        removed_users_message="${REPORT_REMOVED_USERS_COUNT} unauthorized users removed"
        if [ -n "$REPORT_REMOVED_USERS_LIST" ]; then
            removed_users_message="${removed_users_message}: ${REPORT_REMOVED_USERS_LIST}"
        fi
        audit_info "${removed_users_message}."
    else
        audit_warn "No unauthorized users were removed."
    fi

    if [ -n "$REPORT_INSTALLED_PACKAGES" ]; then
        audit_info "Installed during run: ${REPORT_INSTALLED_PACKAGES}."
    fi

    if [ -n "$REPORT_ALREADY_INSTALLED_PACKAGES" ]; then
        audit_info "Already installed: ${REPORT_ALREADY_INSTALLED_PACKAGES}."
    fi

    if [ -n "$REPORT_REMOVED_PACKAGES" ]; then
        audit_info "Removed during run: ${REPORT_REMOVED_PACKAGES}."
    fi

    if [ -n "$REPORT_ALREADY_ABSENT_PACKAGES" ]; then
        audit_info "Already absent: ${REPORT_ALREADY_ABSENT_PACKAGES}."
    fi
}

# Genere le rapport final d'audit sur disque.
finalize_audit_report() {
    local timestamp
    local status_line

    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    write_audit_summary_lines

    if [ "$AUDIT_STATUS" = "PASS" ]; then
        status_line="PASS"
    else
        status_line="FAIL"
    fi

    {
        printf '===============================================\n'
        printf ' HARDENING AUDIT REPORT - %s\n' "$timestamp"
        printf '===============================================\n\n'
        printf '%s' "$AUDIT_LINES"
        printf '\n===============================================\n'
        printf ' COMPLIANCE STATUS: %s\n' "$status_line"
        printf '===============================================\n'
    } > "$AUDIT_REPORT_FILE"

    log "INFO" "Audit report generated at ${AUDIT_REPORT_FILE}"
}

# Attend que les verrous apt soient liberes (avec timeout).
wait_for_apt_lock() {
    local timeout="${APT_LOCK_TIMEOUT:-120}"
    local waited=0

    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 \
       || fuser /var/lib/dpkg/lock >/dev/null 2>&1 \
       || fuser /var/lib/apt/lists/lock >/dev/null 2>&1 \
       || fuser /var/cache/apt/archives/lock >/dev/null 2>&1; do
        if [ "$waited" -ge "$timeout" ]; then
            log "ERROR" "APT lock wait timeout reached after ${timeout} seconds"
            audit_warn "APT was busy for too long; package operations were skipped."
            return 1
        fi

        log "INFO" "APT is locked by another process, waiting..."
        sleep 5
        waited=$((waited + 5))
    done

    log "INFO" "APT lock released"
}

# Lance apt-get en mode non interactif avec gestion des verrous.
apt_run() {
    wait_for_apt_lock || return 1

    DEBIAN_FRONTEND=noninteractive "$APT_GET_BIN" "$@" \
        && log "INFO" "APT command succeeded: apt-get $*" \
        || {
            log "ERROR" "APT command failed: apt-get $*"
            return 1
        }
}

# Durcit la partie systeme: update/upgrade, installation et suppression de paquets.
harden_system() {
    local package_name
    local update_failed="false"
    local upgrade_failed="false"

    log "INFO" "Starting system hardening"

    if ! apt_run update; then
        update_failed="true"
    fi

    if ! apt_run upgrade -y; then
        upgrade_failed="true"
    fi

    if [ "$update_failed" = "true" ] || [ "$upgrade_failed" = "true" ]; then
        audit_warn "Package updates were not fully applied."
    else
        audit_info "Package repositories updated and packages upgraded."
    fi

    for package_name in $PACKAGES_REMOVE; do
        if package_installed "$package_name"; then
            if apt_run remove -y "$package_name"; then
                REPORT_REMOVED_PACKAGES="$(append_csv_value "$REPORT_REMOVED_PACKAGES" "$package_name")"
            else
                audit_warn "Failed to remove package ${package_name}."
            fi
        else
            REPORT_ALREADY_ABSENT_PACKAGES="$(append_csv_value "$REPORT_ALREADY_ABSENT_PACKAGES" "$package_name")"
            log "INFO" "Package already absent: ${package_name}"
        fi
    done

    for package_name in $PACKAGES_INSTALL; do
        if package_installed "$package_name"; then
            REPORT_ALREADY_INSTALLED_PACKAGES="$(append_csv_value "$REPORT_ALREADY_INSTALLED_PACKAGES" "$package_name")"
            log "INFO" "Package already installed: ${package_name}"
        else
            if apt_run install -y "$package_name"; then
                REPORT_INSTALLED_PACKAGES="$(append_csv_value "$REPORT_INSTALLED_PACKAGES" "$package_name")"
            else
                audit_warn "Failed to install package ${package_name}."
            fi
        fi
    done

    log "INFO" "System hardening completed successfully"
}