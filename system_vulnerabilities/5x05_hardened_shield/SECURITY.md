# Hardened Shield - Security Architecture

> **NovaTech Solutions**, production base image for web deployments
> Version 1.0.0 · Owner: Security Engineering · Classification: Internal

Hardened Shield is the standard container image for NovaTech's web workloads.
It combines in one image, and verifies with an automated audit:

- the system hardening from **5x02**
- the identity and access controls from **5x03**
- the container security practices from **5x04**

This document is the reference for anyone who builds, deploys, audits or
maintains the image.

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Security Controls](#2-security-controls)
3. [Usage Instructions](#3-usage-instructions)
4. [Audit Procedures](#4-audit-procedures)
5. [Maintenance Guidelines](#5-maintenance-guidelines)

---

## 1. Architecture Overview

### 1.1 Components

```
                    Internet / corporate network
                          |                 |
                     TCP 80 (HTTP)       TCP 22 (SSH)
                          |                 |
  ========================|=================|=========================  host
   docker bridge "shield-net" (inter-container traffic disabled)
  ------------------------|-----------------|-------------------------
  | container "hardened-shield"   read-only root, 6 caps, nnp, limits |
  |                       v                 v                          |
  |   PID 1  tini  (signals, zombie reaping)                           |
  |     `-- init-services.sh  (root: runtime checks + supervisor)      |
  |           |-- init-hardening.sh --runtime   (verify 5x02)          |
  |           |-- init-identity.sh  --runtime   (verify 5x03, keys)    |
  |           |-- nginx  :8080  master+workers as appuser (uid 1000)   |
  |           |-- sshd   :22    key-only, AllowGroups sshusers         |
  |           |     `-- session as sysadmin (uid 1001), no sudo/su     |
  |           `-- fail2ban      optional, only with NET_ADMIN          |
  |                                                                    |
  |   writable:  tmpfs /tmp /run /var/lib/nginx /var/lib/fail2ban      |
  |              (noexec,nosuid,nodev)                                 |
  |   volumes:   ssh-hostkeys -> /var/lib/ssh-hostkeys                 |
  |              logs         -> /var/log                              |
  ----------------------------------------------------------------------
```

| Component | Role | Runs as | Port |
|---|---|---|---|
| `tini` | PID 1: forwards signals, reaps zombie processes | root | - |
| `init-services.sh` | Entrypoint: runs the runtime checks, prepares directories, starts and supervises the services, health checks | root | - |
| Nginx (`nginx-core`) | Static web server, rate-limited | **appuser**, master and workers | 8080 (published on 80) |
| OpenSSH | Remote administration | root for privilege separation, then the logged-in user | 22 (published on 22, or `SSH_HOST_PORT`) |
| fail2ban | Bans IPs after failed SSH logins (optional) | root | - |
| `audit.py` | Automated compliance audit | any user, full results as root | - |

### 1.2 Accounts and trust boundaries

| Account | UID | Shell | Authentication | Purpose |
|---|---|---|---|---|
| `root` | 0 | - | password locked, no SSH login, `su` restricted to the empty `sugroup` | Starts sshd only |
| `appuser` | 1000 | `nologin` | none (cannot log in) | Owns and runs Nginx |
| `sysadmin` | 1001 | `bash` | SSH public key (+ optional TOTP), password `*` (unusable) | The only interactive login; member of `sshusers` |

**Trust boundaries:**
1. **Network to Nginx:** anonymous, untrusted traffic. Nginx runs without
   root, with only `GET`/`HEAD` allowed, a request rate limit and a read-only
   web root.
2. **Network to sshd:** an authenticated boundary. Login needs a key on the
   allow-list and membership of `sshusers`; there is no password path.
3. **Container to host:** the kernel isolation boundary, enforced by:
   - dropped capabilities
   - no-new-privileges
   - the seccomp and AppArmor profiles
   - a read-only root filesystem
   - cgroup resource limits

### 1.3 Why the container starts as root

There is deliberately no final `USER` line in the Dockerfile. sshd has to
start as root: it needs privilege separation, its privsep chroot, PAM and the
switch to the logged-in user. The risk is contained in four ways:

- **Nginx never runs as root.** The entrypoint starts it as `appuser` with
  `setpriv --reuid --regid --init-groups --no-new-privs --inh-caps=-all`.
- **Root inside the container is weak.** It keeps only 6 capabilities, with
  no `DAC_OVERRIDE`, `FOWNER`, `SYS_ADMIN`, `NET_ADMIN` or `NET_RAW`.
- **No SUID or SGID binaries remain**, so no-new-privileges blocks every
  path to escalate.
- **The root filesystem is read-only**, so nothing can be persisted in the
  image layers.

### 1.4 Repository layout

| Path | Content |
|---|---|
| `Dockerfile` | Image build: `ubuntu:22.04`, packages, accounts, config, build-time hardening, HEALTHCHECK, OCI labels |
| `docker-compose.yml` | Runtime profile: capabilities, security options, limits, volumes, ports, sysctls |
| `scripts/init-hardening.sh` | System hardening (kernel, filesystem, services, SUID, banner) |
| `scripts/init-identity.sh` | Identity hardening (PAM, lockout, SSH, root lockdown, keys, MFA) |
| `scripts/init-services.sh` | Service startup, supervision, health checks |
| `scripts/audit.py` | Security audit with scores, Markdown and JSON reports |
| `config/` | `sshd_config`, `nginx.conf`, `issue.net`, `pwquality.conf`, `faillock.conf`, `pam-configs/`, `jail.local`, `99-hardening.conf`, `www/` |
| `audit_result.md` | Latest audit report |
| `COMPLIANCE_REPORT.md` | Mapping of the controls to the compliance requirements |

### 1.5 Defense in depth

| Layer | Main controls | Implemented in |
|---|---|---|
| Image | Minimal LTS base, security updates, no compilers or network tools, no SUID, no secrets | `Dockerfile`, `init-hardening.sh --build` |
| Kernel | Network sysctls, kernel.* values documented for the host | `docker-compose.yml`, `99-hardening.conf` |
| Filesystem | Read-only root, `noexec,nosuid,nodev` tmpfs, strict permissions, umask 027 | `docker-compose.yml`, `init-hardening.sh` |
| Identity | Key-only SSH, PAM password policy, lockout, locked root, optional MFA | `init-identity.sh`, `config/` |
| Services | Non-root web server, hardened Nginx, minimal daemons, supervision | `init-services.sh`, `nginx.conf` |
| Container | `cap_drop: ALL` + 6, no-new-privileges, seccomp, AppArmor, resource limits | `docker-compose.yml` |
| Verification | Build-time and start-time checks, automated audit, HEALTHCHECK | `--check` modes, `audit.py` |

---

## 2. Security Controls

Each script applies its controls at build time (`--build`), re-verifies them
at every start (`--runtime`), and can report without changing anything
(`--check`). All scripts are idempotent: a second run changes nothing and
reports `0 fixed`.

### 2.1 System hardening (`init-hardening.sh`)

| Area | Control |
|---|---|
| Kernel parameters | 17 `net.ipv4` settings: no IP forwarding, no ICMP redirects (accept or send), no source routing, reverse-path filtering, martian logging, SYN cookies, broadcast and bogus ICMP ignored. In Docker they are applied by `docker-compose.yml` (`sysctls:`) because `/proc/sys` is read-only in the container. |
| Filesystem permissions | `/etc/shadow` and `/etc/gshadow` 0640 root:shadow, `/etc/passwd` and `/etc/group` 0644, sshd config 0600, `/root` 0700 |
| World-writable files | Searched and fixed; sticky bit enforced on world-writable dirs |
| Limits | Core dumps disabled (`* hard core 0`, `fs.suid_dumpable=0` documented), default `UMASK 027` |
| Mount options | Runtime check that `/tmp` and `/dev/shm` are `noexec,nosuid,nodev` and that `/` is read-only |
| Service minimization | Purges unneeded packages (telnet, ftp, rsh, inetd, avahi, cups, rpcbind, nfs, samba, snmp, mail servers, cron/at, netcat/nmap/socat, compilers…); refuses known unneeded daemons at runtime |
| SUID/SGID audit | Strips every SUID/SGID bit not listed in `SUID_ALLOW` (empty by default); report in `/var/log/hardening/suid_audit.txt` |
| Legal banner | "AUTHORIZED ACCESS ONLY" warning in `/etc/issue` and `/etc/issue.net`, shown before SSH authentication |

### 2.2 Identity and access (`init-identity.sh`)

| Area | Control |
|---|---|
| Password quality (`pam_pwquality`) | Minimum 12 characters, at least one digit, uppercase, lowercase and symbol, 3 changed characters, no username, at most 3 repeats, enforced for root too |
| Password history (`pam_pwhistory`) | Last 5 passwords cannot be reused |
| Password aging (`login.defs`) | Max 90 days, min 1 day, warning 14 days, accounts inactive 30 days after expiry, yescrypt hashing, 3 login retries |
| Account lockout (`pam_faillock`) | 5 failures within 15 min lock the account for 15 min, root included (`even_deny_root`), events audited |
| SSH authentication | `AuthenticationMethods publickey` (+ `keyboard-interactive` with `MFA_ENABLED=true`), no passwords, no empty passwords, `PermitRootLogin no`, `AllowGroups sshusers`, `MaxAuthTries 3`, `LoginGraceTime 30`, `MaxSessions 2`, `MaxStartups 10:30:60` |
| SSH cryptography | Modern key exchange, ciphers and MACs only; weak Diffie-Hellman moduli (< 3072 bits) removed; host keys generated at runtime, never baked in the image |
| SSH attack surface | No TCP, agent or X11 forwarding, no tunnels, no user environment, `ClientAliveInterval 300` / `ClientAliveCountMax 2`, `LogLevel VERBOSE`, `StrictModes yes` |
| Admin keys | Read from `SSH_ADMIN_PUBKEY` or a Docker secret, validated one by one (ed25519, ecdsa, or RSA of 3072 bits or more), stored root-owned in `/run/ssh/authorized_keys/sysadmin` |
| Multi-factor (optional) | `MFA_ENABLED=true` adds TOTP (`pam_google_authenticator`). Fails closed: the container refuses to start without a seed |
| Root lockdown | Password locked, no SSH login, `su` limited to the empty `sugroup` (`pam_wheel`), idle shells closed after 15 min (`TMOUT=900`) |
| Brute force | fail2ban `sshd` jail when the container has `NET_ADMIN`; otherwise faillock + `MaxAuthTries` still apply |

### 2.3 Services (`init-services.sh`, `nginx.conf`)

| Area | Control |
|---|---|
| Non-root web server | Nginx master and workers run as `appuser` on 8080; the startup check fails if any Nginx process runs as root |
| Information disclosure | `server_tokens off`, no directory listing, dotfiles (`.git`, `.env`, `.htpasswd`) return 404 |
| HTTP methods | Only `GET` and `HEAD`; others get 403, `TRACE` gets 405 |
| Security headers | `X-Frame-Options DENY`, `X-Content-Type-Options nosniff`, `Referrer-Policy no-referrer`, `Content-Security-Policy`, `Permissions-Policy` |
| Denial of service | 10 requests/s per IP (burst 20), 20 connections per IP, answering 429 above that; short timeouts, 1 MB body limit, bounded header buffers |
| Startup safety | Pre-start checks: runtime hardening and identity, `sshd -t`, `nginx -t`. Exit code 3 if any fails, so a broken configuration never serves traffic |
| Supervision | If a service dies, the container exits so the orchestrator restarts it (`restart: unless-stopped`) |
| Health checks | `--health`: sshd process + `SSH-2.0` banner, Nginx without root processes + `GET /health = OK`, fail2ban when it was started |
| Logging | SSH: `/var/log/ssh/auth.log`; Nginx: `/var/log/nginx/`; hardening: `/var/log/hardening/`; Docker logs rotated (10 MB × 3) |

### 2.4 Container runtime (`Dockerfile`, `docker-compose.yml`)

| Area | Control |
|---|---|
| Base image | `ubuntu:22.04` LTS, `apt-get upgrade` at build, `--no-install-recommends`, caches and docs removed (about 180 MB, under the 500 MB budget) |
| No secrets | No password, key or token in the Dockerfile, the image layers or the compose file; host keys created at first start |
| Capabilities | `cap_drop: ALL`, then only `CHOWN`, `SETUID`, `SETGID`, `SYS_CHROOT`, `NET_BIND_SERVICE` and `KILL` |
| Privilege escalation | `no-new-privileges:true` and no SUID binaries; `privileged: false` |
| Mandatory access control | Docker's default seccomp profile, AppArmor `docker-default` |
| Filesystem | `read_only: true`; writable tmpfs only, all `noexec,nosuid,nodev` |
| Resource limits | 1 CPU, 512 MB memory with no swap, 200 processes, `nofile` 4096/8192, no core dumps |
| Network | Only ports 80 (web) and 22 (SSH) published; dedicated bridge with inter-container traffic disabled |
| Metadata | OCI labels (version, date, revision, vendor, licence) and `security.*` labels |
| Health | `HEALTHCHECK` every 30 s (timeout 10 s, 3 retries, 30 s start period) |

### 2.5 Controls that belong to the host

A container cannot set the global kernel parameters below. Set them on
every Docker host (for example in `/etc/sysctl.d/99-hardening.conf`); the
audit reports them as failures until you do:

```
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.randomize_va_space = 2
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
```

The host should also run Docker with `userns-remap` or rootless mode,
restrict who can use the Docker socket, and keep the kernel and Docker
Engine patched.

---

## 3. Usage Instructions

### 3.1 Requirements

- Docker Engine 20.10+ with Compose v2 (`docker compose`)
- An SSH key pair for the administrator (ed25519 recommended)
- Host ports 80 and 22 free (if the host runs its own sshd, start with
  `SSH_HOST_PORT=2222` and add `-p 2222` to the `ssh` commands below)

### 3.2 Build

```bash
docker compose build
```

To also record the build date and git revision in the labels:

```bash
docker build -t novatech/hardened-shield:1.0.0 --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" --build-arg VCS_REF="$(git rev-parse --short HEAD)" .
```

The build fails if the hardening or identity scripts fail.

### 3.3 Start

Give the administrator's public key, then start the stack:

```bash
export SSH_ADMIN_PUBKEY="$(cat ~/.ssh/id_ed25519.pub)"
```

```bash
docker compose up -d
```

Wait until the status shows `healthy` (about 10 seconds):

```bash
docker compose ps
```

### 3.4 Access

Web:

```bash
curl -I http://localhost/
```

Administration (key login only):

```bash
ssh sysadmin@localhost
```

On first connection, check the host key fingerprint against the one in the
container logs (`docker compose logs shield | grep -i fingerprint`).

### 3.5 Configuration

| Variable | Default | Purpose |
|---|---|---|
| `SSH_ADMIN_PUBKEY` | - | Admin public key(s), one per line |
| `SSH_ADMIN_PUBKEY_FILE` | `/run/secrets/ssh_admin_pubkey` | Same, from a file or Docker secret |
| `MFA_ENABLED` | `false` | `true` = public key + TOTP |
| `SSH_ADMIN_TOTP_FILE` | `/run/secrets/ssh_admin_totp` | `google-authenticator` file for `sysadmin` |
| `SSH_HOSTKEY_DIR` | `/var/lib/ssh-hostkeys` | Where host keys are kept (volume) |
| `FAIL2BAN_ENABLED` | `false` in compose | `auto` starts fail2ban when iptables works (needs `NET_ADMIN` + `NET_RAW`) |
| `STRICT_HARDENING` | `false` | `true` = refuse to start if a runtime hardening check only warns |

**Enable MFA:**
1. Generate the seed on a trusted machine:
   `google-authenticator -t -d -f -r 3 -R 30 -w 3 -s ./secrets/ssh_admin_totp`
2. Mount it as a Docker secret on `/run/secrets/ssh_admin_totp`.
3. Set `MFA_ENABLED=true` and restart. A login then asks for the key and
   then the TOTP code.

### 3.6 Service management

Run these inside the container (`docker compose exec shield <command>`):

| Command | Effect | Exit codes |
|---|---|---|
| `init-services.sh --status` | Status of each service | 0 healthy, 1 a service is down |
| `init-services.sh --health` | Quiet health check (used by HEALTHCHECK) | 0 healthy, 1 unhealthy |
| `init-services.sh --reload` | Re-check the configs, then reload Nginx and sshd | 0 ok, 1 failure |
| `init-hardening.sh --check` | System hardening compliance, no changes | 0 compliant, 1 not compliant |
| `init-identity.sh --check` | Identity compliance, no changes | 0 compliant, 1 not compliant |

Stop the stack with `docker compose down`. Add `-v` only to also delete the
host keys and the logs.

### 3.7 Using the image as a base

```dockerfile
FROM novatech/hardened-shield:1.0.0
COPY --chown=root:root site/ /var/www/html/
RUN /usr/local/sbin/init-hardening.sh --build
```

Rerun `init-hardening.sh --build` after any package install so that new
SUID bits are removed, then run the audit on the derived image.

---

## 4. Audit Procedures

### 4.1 Running the audit

Run it as root inside the container for complete results:

```bash
docker compose exec shield audit.py
```

| Command | Result |
|---|---|
| `audit.py` | Colored console report |
| `audit.py -o /tmp/audit_result.md` | Also writes the Markdown report |
| `audit.py --json -` | JSON results on stdout (for CI or a SIEM) |
| `audit.py --category identity,service` | Only some categories |
| `audit.py --threshold 90` | Stricter pass threshold |
| `audit.py --note "prod-web-01, monthly audit"` | Adds an environment line to the report |

The root filesystem is read-only, so write reports to `/tmp` and copy them
out:

```bash
docker compose exec shield audit.py -q -o /tmp/audit_result.md
```

```bash
docker compose cp shield:/tmp/audit_result.md ./audit_result.md
```

### 4.2 What is checked

| Category | Prefix | Examples |
|---|---|---|
| Kernel | `KRN` | Network sysctls, ASLR, `kptr_restrict`, `dmesg_restrict`, core dumps |
| Filesystem | `FS` | Sensitive file permissions, world-writable files, SUID/SGID, mount options, read-only root |
| Identity | `IDN` | PAM pwquality / pwhistory / faillock, password aging, effective sshd settings (`sshd -T`), root lockdown, empty passwords, UID 0 accounts |
| Service | `SVC` | Listening ports, Nginx as non-root, HTTP headers and methods, version disclosure, banner, forbidden daemons |
| Container | `CTR` | Capabilities, seccomp, AppArmor, no-new-privileges, cgroup limits, secrets in the environment |

### 4.3 Scoring

- Each control has a severity weight: **critical 10, high 5, medium 3,
  low 1**.
- `PASS` earns the full weight, `WARN` half, `FAIL` nothing. `SKIP`
  (not applicable) is left out of the total.
- Category score = points earned / points possible.
- The overall score is computed the same way over every control.
- **Overall PASS** needs a score of at least the threshold (80 % by default)
  **and** no critical failure.

Exit codes: `0` PASS, `1` FAIL, `2` usage or output error. A pipeline can
block a release on a non-zero exit.

### 4.4 Reading the report

`audit_result.md` contains:
1. **Executive Summary:** the overall verdict, the percentage and a table of
   scores per category.
2. **Findings and Remediation:** every FAIL and WARN with its severity and
   the fix to apply.
3. **Detailed Results:** every control, per category.
4. **Methodology:** the scoring rules.

The latest report scores 97.1 % (PASS, no critical failure). Its 3 failures
are outside the image:
- `kptr_restrict` and `dmesg_restrict` must be set on the host (section 2.5).
- Seccomp was not applied in the test environment; under Docker the default
  profile applies.

### 4.5 When to audit

| When | Who | Action |
|---|---|---|
| Every image build (CI) | Pipeline | Run `audit.py --json`; block the release on exit 1 |
| Every deployment | Operator | `docker compose ps` healthy + `audit.py` on the new container |
| Monthly | Security team | Full audit of every running container; archive the reports |
| After any configuration change | Change owner | Run the `--check` modes and the audit before and after |
| After an incident | Incident lead | Audit, then compare with the last archived report |

### 4.6 Manual verification

The automated audit is complemented by these spot checks from outside the
container:

```bash
ssh -o PreferredAuthentications=password sysadmin@localhost
```
Expected: `Permission denied (publickey)`.

```bash
ssh root@localhost
```
Expected: refused.

```bash
curl -sI http://localhost/ | grep -iE '^server|x-frame|content-security'
```
Expected: `Server: nginx` without a version, plus the headers.

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X TRACE http://localhost/
```
Expected: `405`.

```bash
docker inspect hardened-shield --format '{{.HostConfig.CapDrop}} {{.HostConfig.CapAdd}} {{.HostConfig.ReadonlyRootfs}} {{.HostConfig.SecurityOpt}}'
```
Expected: `[ALL]`, the 6 capabilities, `true`, `no-new-privileges:true`.

---

## 5. Maintenance Guidelines

### 5.1 Patching

- **Rebuild the image at least monthly**, and within 72 hours of a critical
  CVE in Ubuntu, OpenSSH, Nginx, PAM or OpenSSL. The build runs
  `apt-get upgrade`, so a rebuild picks up every security update.
- Rebuild with `docker compose build --pull --no-cache` so the latest
  `ubuntu:22.04` base is used.
- Scan the image before release (for example `trivy image` or
  `docker scout cves`); do not ship known critical vulnerabilities.
- Plan the move to the next Ubuntu LTS before 22.04 standard support ends
  (April 2027).
- Patch the Docker hosts (kernel, Docker Engine, containerd) on the same
  schedule.

### 5.2 Versioning and release

- Use semantic versions (`1.0.1` for patches, `1.1.0` for new controls) and
  never deploy `latest` in production.
- Every release: build, run the audit (must PASS), update `audit_result.md`
  and `COMPLIANCE_REPORT.md`, tag the git commit, then push the image.
- Keep the previous image tag so a release can be rolled back.

### 5.3 Changing a control

1. Make the change in `config/` or the scripts, never by hand in a running
   container (the root filesystem is read-only anyway).
2. Keep the scripts idempotent and their exit codes unchanged.
3. Run the build twice: the second run must report `0 fixed`.
4. Run both `--check` modes and `audit.py`; the score must not drop.
5. Have the change reviewed by Security Engineering.
6. Document it in this file and in `COMPLIANCE_REPORT.md`.

Any exception (for example a SUID binary in `SUID_ALLOW` or an added
capability) needs a written justification, an owner and a review date.

### 5.4 Keys and credentials

| Item | Rotation | Procedure |
|---|---|---|
| Admin SSH keys | Every 12 months, or immediately when someone leaves or a key is exposed | Update `SSH_ADMIN_PUBKEY` or the secret, then `docker compose up -d` |
| SSH host keys | Every 12 months or after compromise | `docker volume rm hardened-shield_ssh-hostkeys`, restart, publish the new fingerprints |
| TOTP seeds | When a device is lost or a person leaves | Generate a new seed, replace the secret, restart |

Never commit keys or seeds to git, and never put them in the Dockerfile or
in `docker-compose.yml`.

### 5.5 Monitoring and log review

- Send `/var/log/ssh/auth.log` and the Nginx logs (the `logs` volume) to the
  central SIEM.
- Alert on:
  - container health changing to `unhealthy`, or repeated restarts
  - faillock lockouts and repeated `Failed publickey` attempts
  - SSH logins outside business hours or from unknown IPs
  - bursts of HTTP 429 or 403 responses
- Review the SUID report `/var/log/hardening/suid_audit.txt` after every
  rebuild; it must stay empty unless an exception was approved.

### 5.6 Incident response

1. **Contain:** stop publishing the ports or disconnect the container from
   the network; keep the container itself running for analysis.
2. **Preserve:** copy the `logs` volume and run `docker diff hardened-shield`.
   Because the root filesystem is read-only, any change can only be in the
   tmpfs mounts or the volumes.
3. **Eradicate:** rotate all keys (section 5.4), rebuild the image from
   source, and redeploy.
4. **Review:** run the audit, compare with the archived reports, and update
   the controls and this document.

### 5.7 Reporting a vulnerability

Report suspected vulnerabilities in this image privately to NovaTech
Security Engineering, not in a public issue. Include the image version
(`docker inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}'`),
the steps to reproduce, and the impact. The team acknowledges reports within
2 business days and fixes critical issues within 7 days.
