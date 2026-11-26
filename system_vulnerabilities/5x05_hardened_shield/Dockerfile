# =============================================================================
# NovaTech Solutions - Hardened Shield base image (Capstone 5x05)
# =============================================================================
# Production base for web deployments: Nginx (web) + OpenSSH (remote admin),
# with the 5x02 system hardening, 5x03 identity controls and 5x04 container
# practices baked in, plus an automated audit (audit.py).
#
# Build:
#   docker build -t novatech/hardened-shield:1.0.0 \
#     --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
#     --build-arg VCS_REF="$(git rev-parse --short HEAD)" .
#
# Run (docker-compose.yml applies the full runtime profile):
#   docker run -d --name shield -p 8080:8080 -p 2222:22 \
#     -e SSH_ADMIN_PUBKEY="$(cat ~/.ssh/id_ed25519.pub)" \
#     novatech/hardened-shield:1.0.0
#
# Audit:
#   docker exec shield audit.py
#
# -----------------------------------------------------------------------------
# Users and privileges
# -----------------------------------------------------------------------------
#   appuser  (UID 1000, nologin)  runs Nginx: master AND workers, port 8080,
#                                 so no web process ever runs as root.
#   sysadmin (UID 1001, sshusers) the only SSH login: public key only
#                                 (+ optional TOTP), no password, no sudo.
#   root                          password locked. PID 1 starts as root only
#                                 because sshd needs it (privilege separation,
#                                 PAM, switching to the logged-in user); the
#                                 entrypoint drops to appuser for Nginx.
#                                 That is why there is no final "USER" line.
#
# -----------------------------------------------------------------------------
# Secrets: NONE in this image
# -----------------------------------------------------------------------------
#   - SSH host keys are deleted at build and generated at first start
#     (persist them with a volume on /var/lib/ssh-hostkeys).
#   - The admin public key comes at runtime: SSH_ADMIN_PUBKEY, or a file in
#     SSH_ADMIN_PUBKEY_FILE / /run/secrets/ssh_admin_pubkey.
#   - The TOTP seed (MFA_ENABLED=true) comes from /run/secrets/ssh_admin_totp.
#   No ENV/ARG/RUN line below holds a password, key or token.
# =============================================================================

# Minimal, LTS, PAM >= 1.4 (pam_faillock, as in 5x03). ~77 MB.
FROM ubuntu:22.04

ARG VERSION=1.0.0
ARG BUILD_DATE=unknown
ARG VCS_REF=unknown
ARG APP_UID=1000
ARG ADMIN_UID=1001

LABEL org.opencontainers.image.title="hardened-shield" \
      org.opencontainers.image.description="Hardened Nginx + OpenSSH base image: system hardening, identity controls, container security, automated audit" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.vendor="NovaTech Solutions" \
      org.opencontainers.image.authors="NovaTech Security Engineering Team" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.base.name="docker.io/library/ubuntu:22.04" \
      org.opencontainers.image.documentation="SECURITY.md" \
      security.non-root-app="appuser" \
      security.ssh-auth="publickey (+ optional TOTP)" \
      security.secrets="none" \
      security.audit="audit.py" \
      security.recommended-run-flags="--cap-drop=ALL --cap-add=CHOWN,SETUID,SETGID,SYS_CHROOT,NET_BIND_SERVICE,KILL --security-opt no-new-privileges:true --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev"

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    TZ=UTC

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Packages: latest security updates (5x01), then only what the image needs,
# without recommends. No compiler, no network tools, no package caches.
# nginx-core, not nginx-light: light is built without limit_req/limit_conn
# (no rate limiting). Its extra dynamic modules are never loaded: nginx.conf
# does not include modules-enabled.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends \
        nginx-core \
        openssh-server \
        libpam-pwquality \
        libpam-google-authenticator \
        fail2ban \
        iptables \
        python3 \
        tini \
        curl \
        ca-certificates \
        procps \
    && apt-get purge -y --auto-remove \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/* /var/log/apt/* \
              /var/log/dpkg.log /usr/share/doc/* /usr/share/man/* \
              /usr/share/info/* /etc/nginx/sites-enabled/* \
              /etc/ssh/ssh_host_*

# Accounts: fixed UIDs, no passwords.
#   sysadmin gets "*" (no usable password, but not "locked", which sshd would
#   refuse even for key logins when UsePAM is off).
RUN groupadd --gid "${APP_UID}" appuser \
    && useradd --uid "${APP_UID}" --gid appuser --no-create-home \
               --home-dir /var/www --shell /usr/sbin/nologin appuser \
    && groupadd --system sshusers \
    && groupadd --gid "${ADMIN_UID}" sysadmin \
    && useradd --uid "${ADMIN_UID}" --gid sysadmin --groups sshusers \
               --create-home --shell /bin/bash sysadmin \
    && usermod -p '*' sysadmin \
    && chmod 0750 /home/sysadmin

# Configuration (hardened sshd, nginx, banner, PAM policy, fail2ban, sysctl)
COPY config/sshd_config         /etc/ssh/sshd_config
COPY config/nginx.conf          /etc/nginx/nginx.conf
COPY config/issue.net           /etc/issue.net
COPY config/issue.net           /etc/issue
COPY config/pwquality.conf      /etc/security/pwquality.conf
COPY config/faillock.conf       /etc/security/faillock.conf
COPY config/pam-configs/        /usr/share/pam-configs/
COPY config/jail.local          /etc/fail2ban/jail.local
COPY config/99-hardening.conf   /etc/sysctl.d/99-hardening.conf
COPY config/www/                /var/www/html/

# Scripts: init-* are root-only (0700), audit.py runs for anyone (0755).
COPY scripts/init-hardening.sh scripts/init-identity.sh scripts/init-services.sh /usr/local/sbin/
COPY scripts/audit.py /usr/local/bin/audit.py
RUN sed -i 's/\r$//' /usr/local/sbin/init-*.sh /usr/local/bin/audit.py \
    && chown root:root /usr/local/sbin/init-*.sh /usr/local/bin/audit.py \
    && chmod 0700 /usr/local/sbin/init-hardening.sh \
                  /usr/local/sbin/init-identity.sh \
                  /usr/local/sbin/init-services.sh \
    && chmod 0755 /usr/local/bin/audit.py

# Apply the static controls at build time (idempotent; they re-check at
# start). This strips SUID/SGID bits, so it runs after every package install.
RUN /usr/local/sbin/init-hardening.sh --build \
    && /usr/local/sbin/init-identity.sh --build

# 8080: Nginx as appuser (no NET_BIND_SERVICE needed).  22: sshd.
EXPOSE 8080 22

# Healthy = nginx up as non-root and GET /health = 200, sshd up and
# answering its SSH-2.0 banner, fail2ban answering when it was started.
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD ["/usr/local/sbin/init-services.sh", "--health"]

STOPSIGNAL SIGTERM

# tini = PID 1: forwards signals, reaps zombies. init-services.sh runs the
# runtime hardening/identity checks, then supervises sshd, nginx, fail2ban.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/sbin/init-services.sh"]
