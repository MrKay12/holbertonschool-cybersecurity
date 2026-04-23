#!/bin/bash

# Applique les regles PASS_MAX_DAYS et PASS_MIN_LEN dans login.defs.
set_login_defs_policy() {
    ensure_file_exists "$LOGIN_DEFS_FILE" || return 1

    set_space_directive "$LOGIN_DEFS_FILE" "PASS_MAX_DAYS" "$PASS_MAX_DAYS" || return 1
    set_space_directive "$LOGIN_DEFS_FILE" "PASS_MIN_LEN" "$PASS_MIN_LEN" || return 1

    log "INFO" "Password policy updated in ${LOGIN_DEFS_FILE}"
}

# Configure la complexite des mots de passe via pam_pwquality.
set_password_complexity_policy() {
    local line

    if [ ! -f "$COMMON_PASSWORD_FILE" ]; then
        log "ERROR" "PAM password file not found: ${COMMON_PASSWORD_FILE}"
        return 1
    fi

    line="password requisite pam_pwquality.so retry=3 minlen=${PASS_MIN_LEN} ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1"

    remove_matching_lines "$COMMON_PASSWORD_FILE" "^[[:space:]]*password[[:space:]]+requisite[[:space:]]+pam_pwquality\\.so([[:space:]].*)?$" || return 1
    ensure_exact_line "$COMMON_PASSWORD_FILE" "$line" || return 1

    log "INFO" "Password complexity policy updated in ${COMMON_PASSWORD_FILE}"
}

# Configure le verrouillage de compte apres echecs d'authentification.
set_lockout_policy() {
    local preauth_line
    local authfail_line
    local account_line

    if [ ! -f "$COMMON_AUTH_FILE" ]; then
        log "ERROR" "PAM auth file not found: ${COMMON_AUTH_FILE}"
        return 1
    fi

    preauth_line="auth required pam_faillock.so preauth silent deny=${FAIL_LOCK_ATTEMPTS} unlock_time=900"
    authfail_line="auth [default=die] pam_faillock.so authfail deny=${FAIL_LOCK_ATTEMPTS} unlock_time=900"
    account_line="account required pam_faillock.so"

    remove_matching_lines "$COMMON_AUTH_FILE" "^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_faillock\\.so[[:space:]]+preauth([[:space:]].*)?$" || return 1
    remove_matching_lines "$COMMON_AUTH_FILE" "^[[:space:]]*auth[[:space:]]+\\[default=die\\][[:space:]]+pam_faillock\\.so[[:space:]]+authfail([[:space:]].*)?$" || return 1
    remove_matching_lines "$COMMON_AUTH_FILE" "^[[:space:]]*account[[:space:]]+required[[:space:]]+pam_faillock\\.so([[:space:]].*)?$" || return 1

    ensure_exact_line "$COMMON_AUTH_FILE" "$preauth_line" || return 1
    ensure_exact_line "$COMMON_AUTH_FILE" "$authfail_line" || return 1
    ensure_exact_line "$COMMON_AUTH_FILE" "$account_line" || return 1

    ensure_file_exists "$FAILLOCK_CONF_FILE" || return 1
    set_equals_directive "$FAILLOCK_CONF_FILE" "deny" "$FAIL_LOCK_ATTEMPTS" || return 1
    set_equals_directive "$FAILLOCK_CONF_FILE" "unlock_time" "900" || return 1

    log "INFO" "Account lockout policy configured"
}

# Retourne succes si l'utilisateur fait partie de la liste preservee.
user_is_preserved() {
    local user_name="$1"
    local preserved_user

    for preserved_user in $PRESERVE_USERS; do
        if [ "$user_name" = "$preserved_user" ]; then
            return 0
        fi
    done

    return 1
}

# Retourne succes si l'utilisateur est dans un groupe admin.
user_is_admin() {
    local user_name="$1"
    local admin_group

    for admin_group in $ADMIN_GROUPS; do
        if group_exists "$admin_group" && user_in_group "$user_name" "$admin_group"; then
            return 0
        fi
    done

    return 1
}

# Supprime les comptes non autorises selon les regles de configuration.
cleanup_users() {
    local user_name uid_value

    log "INFO" "Starting user cleanup"

    while IFS=: read -r user_name _ uid_value _ _ _ _; do
        if [ "$uid_value" -ge "$MIN_UID_TO_CLEAN" ]; then
            if [ "$user_name" = "root" ]; then
                log "INFO" "Skipping root user"
                continue
            fi

            if user_is_preserved "$user_name"; then
                log "INFO" "Skipping preserved user ${user_name}"
                continue
            fi

            if user_is_admin "$user_name"; then
                log "INFO" "Skipping admin user ${user_name}"
                continue
            fi

            if user_exists "$user_name"; then
                userdel -r "$user_name" >/dev/null 2>&1 \
                    && {
                        REPORT_REMOVED_USERS_COUNT=$((REPORT_REMOVED_USERS_COUNT + 1))
                        REPORT_REMOVED_USERS_LIST="$(append_csv_value "$REPORT_REMOVED_USERS_LIST" "$user_name")"
                        log "INFO" "Deleted user ${user_name}"
                    } \
                    || {
                        log "ERROR" "Failed to delete user ${user_name}"
                        return 1
                    }
            else
                log "INFO" "User already absent: ${user_name}"
            fi
        fi
    done < /etc/passwd

    log "INFO" "User cleanup completed"
}

# Verrouille le mot de passe du compte root.
lock_root_account() {
    if passwd -S root 2>/dev/null | awk '{print $2}' | grep -Fxq "L"; then
        log "INFO" "Root password already locked"
        return 0
    fi

    passwd -l root >/dev/null 2>&1 \
        && log "INFO" "Root password locked" \
        || {
            log "ERROR" "Failed to lock root password"
            return 1
        }
}

# Orchestration du hardening identite.
harden_identity() {
    log "INFO" "Starting identity hardening"

    set_login_defs_policy || return 1
    set_password_complexity_policy || return 1
    set_lockout_policy || return 1
    cleanup_users || return 1
    lock_root_account || return 1

    log "INFO" "Identity hardening completed successfully"
}