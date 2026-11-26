# 5x05 - Hardened Shield

Capstone: a production-ready, hardened container image for NovaTech Solutions
that combines the system hardening of **5x02**, the identity controls of
**5x03** and the container practices of **5x04**, with an automated audit.

## Layout

| Path | Role |
|---|---|
| `Dockerfile` | Hardened image: `ubuntu:22.04`, Nginx (as `appuser`, :8080), OpenSSH (:22, key-only), tini, HEALTHCHECK, OCI labels, no secrets |
| `scripts/init-hardening.sh` | 5x02 controls. `--build`: strip SUID/SGID, remove compilers/net tools, lock root, file permissions, banner, no core dumps, umask 027. `--runtime`: verify namespaced sysctls, `/tmp` noexec/nosuid/nodev, read-only root |
| `scripts/init-identity.sh` | 5x03 controls. `--build`: pam_pwquality, pam_pwhistory (5), pam_faillock (5 tries / 15 min), password aging, sshd PAM stack for TOTP, account checks, no baked host key. `--runtime`: host keys, admin public key from env/secret, optional MFA |
| `scripts/init-services.sh` | Entrypoint: runs both runtime checks, prepares tmpfs-safe dirs, validates configs, supervises sshd, nginx (dropped to `appuser`) and fail2ban (when `NET_ADMIN` is granted) |
| `scripts/audit.py` | Automated audit (text / Markdown / JSON), exit 1 on any FAIL |
| `config/` | `sshd_config`, `nginx.conf`, legal banner, `pwquality.conf`, `faillock.conf`, PAM profiles, `jail.local`, sysctl list, web root |

## Quick start

```bash
docker build -t novatech/hardened-shield:1.0.0 .
```

```bash
docker run -d --name shield -p 8080:8080 -p 2222:22 -e SSH_ADMIN_PUBKEY="$(cat ~/.ssh/id_ed25519.pub)" novatech/hardened-shield:1.0.0
```

```bash
ssh -p 2222 sysadmin@localhost
```

```bash
docker exec shield audit.py
```

## Runtime variables

| Variable | Default | Purpose |
|---|---|---|
| `SSH_ADMIN_PUBKEY` | - | Admin public key(s) (ed25519 / ecdsa / RSA >= 3072) |
| `SSH_ADMIN_PUBKEY_FILE` | `/run/secrets/ssh_admin_pubkey` | Same, from a file / Docker secret |
| `MFA_ENABLED` | `false` | `true` = publickey + TOTP; refuses to start without a seed |
| `SSH_ADMIN_TOTP_FILE` | `/run/secrets/ssh_admin_totp` | google-authenticator file for `sysadmin` |
| `SSH_HOSTKEY_DIR` | `/var/lib/ssh-hostkeys` | Mount a volume here to keep host keys across restarts |
| `FAIL2BAN_ENABLED` | `auto` | `false` disables; `auto` starts it when iptables works |
| `STRICT_HARDENING` | `false` | `true` = refuse to start if a runtime hardening check warns |
