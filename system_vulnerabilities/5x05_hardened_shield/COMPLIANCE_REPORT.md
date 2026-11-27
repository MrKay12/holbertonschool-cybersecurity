# Compliance Report - NovaTech Hardened Shield

| Field | Value |
|---|---|
| Organization | NovaTech Solutions |
| System | Hardened Shield container image `novatech/hardened-shield:1.0.0` |
| Report version | 1.0 |
| Report date | 2026-11-27 |
| Assessment date | 2026-11-26 |
| Prepared by | Security Engineering Team |
| Classification | Internal - Confidential |
| Evidence | `audit_result.md` (audit.py 1.0.0), functional tests (section 4.3) |
| Reference frameworks | CIS Docker Benchmark, CIS Ubuntu Linux 22.04 LTS Benchmark, NIST SP 800-53 Rev. 5, NIST SP 800-190 |

---

## 1. Executive Summary

NovaTech Solutions needed a single, hardened container image for its web
deployments. Hardened Shield brings together three earlier hardening efforts
and verifies them automatically:

- the system hardening from **5x02**
- the identity and access controls from **5x03**
- the container security practices from **5x04**

**Conclusion: the image is COMPLIANT and approved for production, with the
conditions listed in section 5.**

| Indicator | Result |
|---|---|
| Overall audit score | **97.1 %** (threshold 80 %) |
| Overall status | ✅ **PASS** |
| Controls tested | 101 automated + 14 functional tests |
| Automated results | 96 PASS · 2 WARN · 3 FAIL · 0 SKIP |
| Critical failures | **0** |
| Functional tests | 14 / 14 passed |
| Image size | ~180 MB (limit 500 MB) |
| Secrets in the image | None |

**Key strengths:**
- No web process runs as root: Nginx master and workers run as `appuser`.
- SSH accepts public keys only. Root cannot log in and no password works,
  with optional TOTP on top.
- The runtime is locked down:
  - read-only root filesystem
  - every capability dropped except 6
  - no-new-privileges, with no SUID binaries left
  - CPU, memory and process limits
- The image contains no secrets and no compilers or network tools, and every
  security update was applied at build time.
- Every control is re-checked at each start. A non-compliant container
  refuses to serve traffic.

**What remains:** none of the 3 failures is caused by the image itself.
- **Two are host settings:** `kptr_restrict` and `dmesg_restrict` must be
  set on the Docker host.
- **One comes from the test environment:** seccomp was not applied there.
  The production runtime applies Docker's default seccomp profile.

These are tracked as residual risks with owners and deadlines (section 5).

---

## 2. Scope

### 2.1 In scope

| Item | Description |
|---|---|
| Container image | `Dockerfile`: base `ubuntu:22.04`, packages, accounts, configuration, build-time hardening, HEALTHCHECK, labels |
| Runtime profile | `docker-compose.yml`: capabilities, security options, resource limits, volumes, ports, sysctls |
| Hardening scripts | `init-hardening.sh` (system), `init-identity.sh` (identity), `init-services.sh` (services) |
| Configuration | `config/`: `sshd_config`, `nginx.conf`, PAM (`pwquality.conf`, `faillock.conf`, profiles), `jail.local`, `99-hardening.conf`, banner |
| Services | Nginx (web, TCP 8080 published on 80), OpenSSH (administration, TCP 22 published on 2222) |
| Audit tooling | `audit.py` and its report `audit_result.md` |

### 2.2 Out of scope

- The Docker hosts: kernel, Docker Engine, host firewall and host sshd.
  Section 5 records the host requirements that this image depends on.
- Application code and content deployed on top of the image.
- Orchestration (Kubernetes, Swarm), load balancers, TLS termination, WAF.
- Centralized logging, SIEM and backup infrastructure.
- Penetration testing by a third party.

### 2.3 Test environment

The audit and functional tests were run on a build of the exact Dockerfile.
The build used the official Ubuntu 22.04.5 base image (checksum verified)
and ran in a rootless, user-namespace sandbox that reproduces the
`docker-compose.yml` profile:

- read-only root filesystem and `noexec,nosuid,nodev` tmpfs mounts
- only the 6 approved capabilities, plus no-new-privileges
- limits of 512 MiB memory, 200 processes and 1 CPU

**Limitations of this environment:**
- It does not load Docker's seccomp and AppArmor profiles.
- Host-level `kernel.*` values are those of the test machine.

Both points are addressed in section 5.

### 2.4 Methodology

1. **Build-time verification:** both hardening scripts run during the build
   and fail it on any error. A second run made 0 changes, which confirms the
   scripts are idempotent.
2. **Start-time verification:** `init-hardening.sh --check` and
   `init-identity.sh --check` returned exit code 0 (compliant).
3. **Automated audit:** `audit.py` ran as root inside the running container.
   It checked 101 controls in 5 categories, weighted by severity
   (critical 10, high 5, medium 3, low 1).
   - `WARN` earns half the weight; `SKIP` is excluded.
   - PASS requires at least 80 % **and** no critical failure.
4. **Functional tests:** SSH, HTTP and privilege-escalation tests run from
   outside and inside the container.

---

## 3. Controls Implemented

### 3.1 Control summary

| Domain | Controls | Implemented in | Frameworks |
|---|---|---|---|
| Kernel hardening | 17 network sysctls (no forwarding, redirects, source routing; rp_filter, SYN cookies, martians); host kernel values documented | `99-hardening.conf`, `docker-compose.yml`, `init-hardening.sh` | CIS Ubuntu §3 (network), NIST SC-5, SC-7 |
| Filesystem security | Read-only root, `noexec,nosuid,nodev` tmpfs, sensitive file permissions, no world-writable files, SUID/SGID removed, no core dumps, umask 027 | `init-hardening.sh`, `docker-compose.yml` | CIS Ubuntu §1, §6; CIS Docker (read-only root), NIST AC-3, AC-6, CM-6 |
| Service minimization | Unneeded packages purged (telnet, ftp, rsh, inetd, cron/at, netcat, nmap, compilers…), forbidden daemons blocked, only 2 services | `Dockerfile`, `init-hardening.sh` | CIS Ubuntu §2, NIST CM-7 |
| Password policy | pwquality (12 chars, 4 classes, root included), history 5, aging 90/1/14, inactive 30 days, yescrypt | `pwquality.conf`, `init-identity.sh` | CIS Ubuntu §5, NIST IA-5 |
| Account lockout | pam_faillock: 5 failures / 15 min, 15 min lock, root included | `faillock.conf`, `init-identity.sh` | CIS Ubuntu §5, NIST AC-7 |
| SSH hardening | Public key only (+ optional TOTP), no root, `AllowGroups sshusers`, `MaxAuthTries 3`, modern crypto, DH ≥ 3072, no forwarding, idle timeout, verbose logging | `sshd_config`, `init-identity.sh` | CIS Ubuntu §5 (SSH), NIST AC-17, IA-2, SC-8 |
| Root lockdown | Password locked, no SSH, `su` restricted (`pam_wheel`, empty group), `TMOUT=900` | `init-identity.sh` | CIS Ubuntu §5, NIST AC-6(2), AC-12 |
| Legal banner | "Authorized access only" banner before authentication | `issue.net`, `init-hardening.sh` | CIS Ubuntu §1 (banners), NIST AC-8 |
| Web server | Non-root Nginx, `server_tokens off`, security headers, GET/HEAD only, dotfiles blocked, rate and connection limits, timeouts | `nginx.conf`, `init-services.sh` | NIST SC-5, SI-10, CM-7 |
| Service management | Pre-start config validation, supervision, health checks, fail-closed startup | `init-services.sh`, `Dockerfile` | NIST SI-6, CP-10 |
| Container image | Minimal LTS base, updates applied, no secrets, OCI labels, HEALTHCHECK, < 500 MB | `Dockerfile` | CIS Docker §4 (images), NIST SP 800-190, SI-2 |
| Container runtime | `cap_drop: ALL` + 6, no-new-privileges, seccomp, AppArmor, read-only root, CPU/memory/PID limits, isolated network | `docker-compose.yml` | CIS Docker §5 (runtime), NIST AC-6, SC-39 |
| Audit and logging | Automated audit with scores, SSH verbose logs, Nginx logs, SUID report, log rotation | `audit.py`, `init-services.sh` | NIST AU-2, AU-12, CA-7 |

### 3.2 Key control parameters

| Control | Required value | Implemented value | Status |
|---|---|---|:---:|
| Web server user | non-root | `appuser` (UID 1000), master and workers | ✅ |
| SSH authentication | key-based | `AuthenticationMethods publickey` | ✅ |
| SSH root login | denied | `PermitRootLogin no` | ✅ |
| SSH password login | denied | `PasswordAuthentication no`; keyboard-interactive only used as a second factor after the key (`AuthenticationMethods`) | ✅ |
| SSH max auth tries | ≤ 4 | 3 | ✅ |
| Minimum password length | ≥ 12 | 12 | ✅ |
| Password complexity | 4 classes | digit, upper, lower, symbol | ✅ |
| Password history | ≥ 5 | 5 | ✅ |
| Lockout threshold | ≤ 5 | 5 failures / 15 min | ✅ |
| Lockout duration | ≥ 15 min | 900 s | ✅ |
| Root password | locked | `passwd -l` | ✅ |
| SUID/SGID binaries | none unless justified | 0 | ✅ |
| Capabilities | minimal | 6 (CHOWN, SETUID, SETGID, SYS_CHROOT, NET_BIND_SERVICE, KILL) | ✅ |
| no-new-privileges | enabled | `no-new-privileges:true` | ✅ |
| Root filesystem | read-only | `read_only: true` | ✅ |
| Resource limits | set | 1 CPU, 512 MB, 200 PIDs | ✅ |
| Secrets in image | none | none | ✅ |
| Image size | < 500 MB | ~180 MB | ✅ |
| Health check | present | every 30 s, 3 retries | ✅ |
| Published ports | web + SSH only | 80 → 8080, 2222 → 22 | ✅ |

---

## 4. Test Results

### 4.1 Automated audit (`audit.py`)

Full detail: [`audit_result.md`](audit_result.md).

| Category | Score | Status | Pass | Warn | Fail |
|---|---:|:---:|---:|---:|---:|
| Kernel hardening | 93.5 % | ✅ PASS | 18 | 0 | 2 |
| Filesystem security | 100.0 % | ✅ PASS | 16 | 0 | 0 |
| Identity security | 100.0 % | ✅ PASS | 20 | 0 | 0 |
| Service security | 99.6 % | ✅ PASS | 30 | 1 | 0 |
| Container security | 89.2 % | ✅ PASS | 12 | 1 | 1 |
| **Overall** | **97.1 %** | ✅ **PASS** | **96** | **2** | **3** |

### 4.2 Non-passing controls

| ID | Severity | Result | Finding | Cause | Disposition |
|---|---|:---:|---|---|---|
| CTR-04 | High | FAIL | Seccomp filter not active | Test sandbox does not load Docker's seccomp profile | Environment limitation. Production uses Docker's default profile (never `unconfined`). Verify after deployment (R-01) |
| KRN-16 | Medium | FAIL | `kernel.kptr_restrict = 0` | Host kernel setting, not settable from a container | Host requirement (R-02) |
| KRN-17 | Low | FAIL | `kernel.dmesg_restrict = 0` | Host kernel setting | Host requirement (R-02) |
| CTR-05 | Medium | WARN | AppArmor profile not applied | Test sandbox; `docker-compose.yml` sets `apparmor:docker-default` | Verify after deployment (R-01) |
| SVC-31 | Low | WARN | fail2ban not running | Needs `NET_ADMIN`, deliberately not granted | Accepted risk (R-03) |

### 4.3 Functional tests

| # | Test | Expected | Result |
|---|---|---|:---:|
| F-01 | Build runs both hardening scripts | build succeeds | ✅ |
| F-02 | Second build run (idempotency) | 0 changes | ✅ 0 fixed |
| F-03 | `init-hardening.sh --check` and `init-identity.sh --check` | exit 0 | ✅ |
| F-04 | Container health (`init-services.sh --status` / `--health`) | HEALTHY, exit 0 | ✅ |
| F-05 | Restart services already running | "nothing to start", no duplicate | ✅ |
| F-06 | SSH login as `sysadmin` with the authorized key | success (uid 1001, group sshusers) | ✅ |
| F-07 | SSH login as `root` | refused | ✅ |
| F-08 | SSH password authentication | refused (publickey only) | ✅ |
| F-09 | `su` from the `sysadmin` session | denied (no SUID) | ✅ |
| F-10 | Nginx processes | none running as root | ✅ |
| F-11 | HTTP `Server` header | no version shown | ✅ |
| F-12 | HTTP security headers | all present | ✅ |
| F-13 | `TRACE` / `PUT` / `DELETE` / `GET /.git` | 405 / 403 / 403 / 404 | ✅ |
| F-14 | 60 rapid HTTP requests | rate limiting answers 429 (37 of 60) | ✅ |

### 4.4 Defects found and corrected during testing

Testing found 4 defects in the image. They were fixed and re-tested before
this report:

| # | Defect | Impact | Correction |
|---|---|---|---|
| D-01 | `pam-auth-update` silently skipped the update because of a manual PAM edit, so `pam_faillock` was not active | No account lockout | PAM profiles applied first and re-verified; manual edits after |
| D-02 | Directory ownership set before permissions, which needs `CAP_FOWNER` | Container could not start with the minimal capability set | Permissions set first, owner last |
| D-03 | Subdirectories created inside an `appuser` 0750 directory, which needs `CAP_DAC_OVERRIDE` | Same | Subdirectories created before the parent is handed over |
| D-04 | `nginx-light` has no rate-limiting module | Nginx refused the configuration | Switched to `nginx-core`; per-IP connection limit added |

---

## 5. Residual Risks

Risk rating = likelihood × impact (Low / Medium / High).

| ID | Risk | Likelihood | Impact | Rating | Treatment | Owner | Due |
|---|---|:---:|:---:|:---:|---|---|---|
| R-01 | Seccomp or AppArmor not applied in production (a host without AppArmor, or someone setting `unconfined`), which leaves a larger kernel attack surface | Low | High | **Medium** | **Mitigate:** keep the defaults in `docker-compose.yml`; run `audit.py` after every deployment and require CTR-04 and CTR-05 to PASS | Platform team | Each deployment |
| R-02 | Host kernel settings `kptr_restrict` and `dmesg_restrict` not set, so kernel addresses and logs can leak to help exploits | Medium | Medium | **Medium** | **Mitigate:** add them to the host baseline (`/etc/sysctl.d/`, see SECURITY.md §2.5) | Infrastructure team | 2026-12-15 |
| R-03 | fail2ban disabled (no `NET_ADMIN`), so attacking IPs are not banned at the network level | Medium | Low | **Low** | **Accept:** key-only SSH, faillock and `MaxAuthTries 3` make brute force ineffective; giving `NET_ADMIN` would be a bigger risk | Security Engineering | Review 2027-05 |
| R-04 | The container starts as root because sshd needs it, so an sshd vulnerability could give root inside the container | Low | Medium | **Low** | **Mitigate:** root is limited by 6 capabilities, no-new-privileges, read-only root and seccomp. Patch OpenSSH quickly. Long term, consider moving SSH out of the image | Security Engineering | Review 2027-05 |
| R-05 | SSH published on the network (port 2222) | Medium | Medium | **Medium** | **Mitigate:** restrict port 2222 to the admin network or VPN at the firewall | Infrastructure team | 2026-12-15 |
| R-06 | No TLS in the image: HTTP on port 80 is plain text | High | Medium | **Medium** | **Transfer:** TLS terminates at the load balancer or reverse proxy (out of scope); do not expose port 80 directly to the Internet | Platform team | Before go-live |
| R-07 | Ubuntu 22.04 standard support ends in April 2027; new vulnerabilities in the packages | Medium | Medium | **Medium** | **Mitigate:** monthly rebuild and image scan; plan migration to the next LTS | Security Engineering | Plan by 2027-02 |
| R-08 | Results come from a sandbox that reproduces Docker, not from Docker itself | Low | Low | **Low** | **Mitigate:** repeat the audit on the first production deployment and attach the report to this document | Security Engineering | First deployment |

**Conditions of approval:**
1. R-02 and R-05 are done before go-live.
2. R-06 is done before go-live: port 80 is reachable only through the TLS
   front end.
3. The audit is repeated under Docker on the production host: the result
   must be PASS with CTR-04 and CTR-05 passing.

---

## 6. Sign-off

By signing, the approvers confirm they have reviewed this report and its
evidence and accept the residual risks in section 5 under the stated
conditions.

**Decision:** ☑ Approved with conditions · ☐ Approved · ☐ Rejected

| Role | Name | Decision | Signature | Date |
|---|---|---|---|---|
| Prepared by - Security Engineer | | Submitted | | 2026-11-27 |
| Reviewed by - Security Engineering Lead | | | | |
| Approved by - Chief Information Security Officer | | | | |
| Accepted by - Platform / Infrastructure Owner | | | | |

### Revision history

| Version | Date | Author | Change |
|---|---|---|---|
| 1.0 | 2026-11-27 | Security Engineering Team | First release for `hardened-shield:1.0.0` |

**Next review:** 2027-05-27, or sooner after a major release, a critical
vulnerability or a security incident.
