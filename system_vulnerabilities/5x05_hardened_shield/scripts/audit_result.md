# Security Audit Report - NovaTech Hardened Shield

| Field | Value |
|---|---|
| Target | `shield` |
| Date | 2026-11-26 15:33:00 UTC |
| Operating system | Ubuntu 22.04.5 LTS (kernel 7.2.15+kali-amd64) |
| Tool | audit.py 1.0.0 |
| Privileges | root |
| Pass threshold | 80.0 % and no critical failure |
| Environment | Rootless sandbox replay of the Dockerfile (official Ubuntu 22.04.5 base, user namespaces): read-only root, noexec/nosuid/nodev tmpfs, capabilities limited to CHOWN SETUID SETGID SYS_CHROOT NET_BIND_SERVICE KILL, no-new-privileges, 512 MiB / 200 PIDs / 1 CPU. Docker seccomp and AppArmor profiles are not applied in this sandbox; host kernel.* values are those of the build machine. |

## 1. Executive Summary

**Overall result: ✅ PASS - 97.1 %**

101 controls audited: **96 passed**, 2 warnings, **3 failed**, 0 skipped. Critical failures: **0**.

| Category | Score | Status | Pass | Warn | Fail | Skip |
|---|---:|:---:|---:|---:|---:|---:|
| Kernel hardening | 93.5 % | PASS | 18 | 0 | 2 | 0 |
| Filesystem security | 100.0 % | PASS | 16 | 0 | 0 | 0 |
| Identity security | 100.0 % | PASS | 20 | 0 | 0 | 0 |
| Service security | 99.6 % | PASS | 30 | 1 | 0 | 0 |
| Container security | 89.2 % | PASS | 12 | 1 | 1 | 0 |
| **Overall** | **97.1 %** | **PASS** | 96 | 2 | 3 | 0 |

## 2. Findings and Remediation

| ID | Severity | Status | Finding | Observed | Remediation |
|---|---|---|---|---|---|
| CTR-04 | HIGH | FAIL | Seccomp filter active | Seccomp: 0 | keep Docker's default seccomp profile (never seccomp=unconfined) |
| KRN-16 | MEDIUM | FAIL | Kernel pointers hidden (host) | kernel.kptr_restrict = 0 | on the Docker host: sysctl -w kernel.kptr_restrict=1 (/etc/sysctl.d/) |
| KRN-17 | LOW | FAIL | dmesg restricted to privileged users (host) | kernel.dmesg_restrict = 0 | on the Docker host: sysctl -w kernel.dmesg_restrict=1 (/etc/sysctl.d/) |
| CTR-05 | MEDIUM | WARN | AppArmor/LSM profile applied | unconfined | keep docker-default AppArmor profile |
| SVC-31 | LOW | WARN | Brute-force banning (fail2ban) running | not started (needs NET_ADMIN); faillock + MaxAuthTries still apply | cap_add: NET_ADMIN, NET_RAW to enable fail2ban |

## 3. Detailed Results

### 3.1 Kernel hardening - 93.5 % (PASS)

| ID | Control | Severity | Status | Observed |
|---|---|---|:---:|---|
| KRN-01 | IP forwarding disabled (no routing between networks) | high | PASS | net.ipv4.ip_forward = 0 |
| KRN-02 | ICMP redirects ignored (all) | medium | PASS | net.ipv4.conf.all.accept_redirects = 0 |
| KRN-03 | ICMP redirects ignored (default) | medium | PASS | net.ipv4.conf.default.accept_redirects = 0 |
| KRN-04 | Secure ICMP redirects ignored | low | PASS | net.ipv4.conf.all.secure_redirects = 0 |
| KRN-05 | ICMP redirects not sent (all) | medium | PASS | net.ipv4.conf.all.send_redirects = 0 |
| KRN-06 | ICMP redirects not sent (default) | medium | PASS | net.ipv4.conf.default.send_redirects = 0 |
| KRN-07 | Reverse-path filtering (anti-spoofing, all) | medium | PASS | net.ipv4.conf.all.rp_filter = 1 |
| KRN-08 | Reverse-path filtering (default) | medium | PASS | net.ipv4.conf.default.rp_filter = 1 |
| KRN-09 | Source-routed packets rejected (all) | high | PASS | net.ipv4.conf.all.accept_source_route = 0 |
| KRN-10 | Source-routed packets rejected (default) | high | PASS | net.ipv4.conf.default.accept_source_route = 0 |
| KRN-11 | Martian packets logged | low | PASS | net.ipv4.conf.all.log_martians = 1 |
| KRN-12 | TCP SYN cookies (SYN flood protection) | high | PASS | net.ipv4.tcp_syncookies = 1 |
| KRN-13 | Broadcast ICMP ignored (smurf) | medium | PASS | net.ipv4.icmp_echo_ignore_broadcasts = 1 |
| KRN-14 | Bogus ICMP errors ignored | low | PASS | net.ipv4.icmp_ignore_bogus_error_responses = 1 |
| KRN-15 | Full ASLR (host) | high | PASS | kernel.randomize_va_space = 2 |
| KRN-16 | Kernel pointers hidden (host) | medium | FAIL | kernel.kptr_restrict = 0 |
| KRN-17 | dmesg restricted to privileged users (host) | low | FAIL | kernel.dmesg_restrict = 0 |
| KRN-18 | Protected symlinks (host) | medium | PASS | fs.protected_symlinks = 1 |
| KRN-19 | Protected hardlinks (host) | medium | PASS | fs.protected_hardlinks = 1 |
| KRN-20 | No core dumps of SUID programs (host) | medium | PASS | fs.suid_dumpable = 0 |

### 3.2 Filesystem security - 100.0 % (PASS)

| ID | Control | Severity | Status | Observed |
|---|---|---|:---:|---|
| FS-01 | Root filesystem mounted read-only | high | PASS | ro,nosuid,nodev |
| FS-02 | /tmp mounted noexec,nosuid,nodev | high | PASS | noexec,nosuid,nodev |
| FS-03 | /dev/shm mounted noexec,nosuid,nodev | medium | PASS | noexec,nosuid,nodev |
| FS-04 | No SUID/SGID binaries | high | PASS | 0 found |
| FS-05 | No world-writable files | medium | PASS | 0 found |
| FS-06 | World-writable directories have the sticky bit | medium | PASS | 0 found |
| FS-07 | No unowned files | low | PASS | 0 found |
| FS-08 | /etc/shadow root:shadow 640 or stricter | high | PASS | root:shadow 640 |
| FS-09 | /etc/gshadow root:shadow 640 or stricter | medium | PASS | root:shadow 640 |
| FS-10 | /etc/passwd root:root 644 or stricter | medium | PASS | root:root 644 |
| FS-11 | /etc/group root:root 644 or stricter | low | PASS | root:root 644 |
| FS-12 | /etc/ssh/sshd_config root:root 600 or stricter | medium | PASS | root:root 600 |
| FS-13 | /root root:root 700 or stricter | medium | PASS | root:root 700 |
| FS-14 | Web content not writable by appuser | high | PASS | root-owned, read-only for appuser |
| FS-15 | Core dumps disabled | low | PASS | limits.d hard core 0 |
| FS-16 | Default umask 027 or stricter | low | PASS | UMASK 027 |

### 3.3 Identity security - 100.0 % (PASS)

| ID | Control | Severity | Status | Observed |
|---|---|---|:---:|---|
| IDN-01 | Password minimum length >= 12 | high | PASS | minlen = 12 |
| IDN-02 | Password requires digit, upper, lower, special | medium | PASS | required: dcredit, ucredit, lcredit, ocredit |
| IDN-03 | Password complexity enforced for root | low | PASS | enforce_for_root |
| IDN-04 | pam_pwquality active | high | PASS | common-password |
| IDN-05 | Password history (last 5 refused) | medium | PASS | remember=5 |
| IDN-06 | Account lockout (pam_faillock) active | high | PASS | preauth + authfail |
| IDN-07 | Lockout after <= 5 failures | medium | PASS | deny = 5 |
| IDN-08 | Lockout duration >= 15 min | medium | PASS | unlock_time = 900 |
| IDN-09 | Lockout applies to root | low | PASS | even_deny_root |
| IDN-10 | Password maximum age <= 90 days | medium | PASS | PASS_MAX_DAYS 90 |
| IDN-11 | Password minimum age >= 1 day | low | PASS | PASS_MIN_DAYS 1 |
| IDN-12 | Strong password hashing | medium | PASS | ENCRYPT_METHOD YESCRYPT |
| IDN-13 | Only root has UID 0 | critical | PASS | root |
| IDN-14 | System accounts cannot log in | medium | PASS | all nologin |
| IDN-15 | appuser (web) has no login shell | high | PASS | /usr/sbin/nologin |
| IDN-16 | Root password locked | critical | PASS | locked |
| IDN-17 | No account with an empty password | critical | PASS | none |
| IDN-18 | sysadmin is key-only (no password) | medium | PASS | no usable password |
| IDN-19 | su restricted (pam_wheel) | low | PASS | pam_wheel |
| IDN-20 | Idle shell timeout <= 15 min | low | PASS | TMOUT=900 |

### 3.4 Service security - 99.6 % (PASS)

| ID | Control | Severity | Status | Observed |
|---|---|---|:---:|---|
| SVC-01 | SSH server running | high | PASS | 1 sshd process(es) |
| SVC-02 | SSH: root login refused | critical | PASS | PermitRootLogin no [sshd -T (effective)] |
| SVC-03 | SSH: password authentication disabled | critical | PASS | PasswordAuthentication no [sshd -T (effective)] |
| SVC-04 | SSH: empty passwords refused | critical | PASS | PermitEmptyPasswords no [sshd -T (effective)] |
| SVC-05 | SSH: public key authentication | high | PASS | PubkeyAuthentication yes [sshd -T (effective)] |
| SVC-06 | SSH: X11 forwarding disabled | medium | PASS | X11Forwarding no [sshd -T (effective)] |
| SVC-07 | SSH: TCP forwarding disabled (no pivoting) | medium | PASS | AllowTcpForwarding no [sshd -T (effective)] |
| SVC-08 | SSH: agent forwarding disabled | low | PASS | AllowAgentForwarding no [sshd -T (effective)] |
| SVC-09 | SSH: tunnels disabled | medium | PASS | PermitTunnel no [sshd -T (effective)] |
| SVC-10 | SSH: user environment ignored | medium | PASS | PermitUserEnvironment no [sshd -T (effective)] |
| SVC-11 | SSH: host-based authentication disabled | medium | PASS | HostbasedAuthentication no [sshd -T (effective)] |
| SVC-12 | SSH: verbose logging (key fingerprints) | low | PASS | LogLevel VERBOSE [sshd -T (effective)] |
| SVC-13 | SSH: MaxAuthTries <= 3 | medium | PASS | MaxAuthTries 3 |
| SVC-14 | SSH: LoginGraceTime <= 60 s | low | PASS | LoginGraceTime 30 |
| SVC-15 | SSH: idle sessions closed | low | PASS | ClientAliveInterval 300 |
| SVC-16 | SSH: login restricted to a group/user list | high | PASS | AllowGroups sshusers |
| SVC-17 | SSH: legal banner displayed | low | PASS | Banner /etc/issue.net |
| SVC-18 | SSH: no weak ciphers, MACs or key exchange | high | PASS | modern algorithms only |
| SVC-19 | SSH: no host key baked into the image | high | PASS | generated at runtime |
| SVC-20 | SSH: host private keys mode 600 | high | PASS | 2 key(s) 600 |
| SVC-21 | Web server running | high | PASS | 13 nginx process(es) |
| SVC-22 | Web server runs without root (master + workers) | critical | PASS | uids [1000] |
| SVC-23 | Web health endpoint answers 200 | high | PASS | HTTP 200 |
| SVC-24 | Web server version hidden | medium | PASS | Server: nginx |
| SVC-25 | Web security headers present | medium | PASS | XFO, XCTO, CSP, Referrer-Policy |
| SVC-26 | Web: hidden files not served | medium | PASS | /.git/config -> HTTP 404 |
| SVC-27 | Web: only GET/HEAD allowed | medium | PASS | TRACE/PUT/DELETE refused |
| SVC-28 | Only expected ports listening (22, 8080) | high | PASS | listening: [22, 8080] |
| SVC-29 | No unneeded daemons running | medium | PASS | none |
| SVC-30 | No compilers or network attack tools | medium | PASS | none |
| SVC-31 | Brute-force banning (fail2ban) running | low | WARN | not started (needs NET_ADMIN); faillock + MaxAuthTries still apply |

### 3.5 Container security - 89.2 % (PASS)

| ID | Control | Severity | Status | Observed |
|---|---|---|:---:|---|
| CTR-01 | Running inside a container | low | PASS | container detected |
| CTR-02 | PID 1 is a minimal init (signals, zombies) | low | PASS | tini |
| CTR-03 | no-new-privileges enforced | high | PASS | NoNewPrivs: 1 |
| CTR-04 | Seccomp filter active | high | FAIL | Seccomp: 0 |
| CTR-05 | AppArmor/LSM profile applied | medium | WARN | unconfined |
| CTR-06 | Not a privileged container | critical | PASS | 6 capabilities in bounding set |
| CTR-07 | Dangerous capabilities dropped | high | PASS | bounding set: CHOWN, KILL, NET_BIND_SERVICE, SETGID, SETUID, SYS_CHROOT |
| CTR-08 | Docker socket not mounted | critical | PASS | absent |
| CTR-09 | /proc/sys read-only | medium | PASS | ro,relatime |
| CTR-10 | Memory limit set | medium | PASS | 512 MiB |
| CTR-11 | Process limit set (fork bombs) | medium | PASS | 200 |
| CTR-12 | CPU limit set | low | PASS | 100000 100000 |
| CTR-13 | No secrets in environment variables | high | PASS | 5 variables, none sensitive |
| CTR-14 | Application workload runs as a non-root user | high | PASS | nginx as uid 1000 |

## 4. Methodology

- Checks run inside the container and read live state: `/proc`, `/sys/fs/cgroup`, PAM and login files, the effective `sshd -T` configuration, and HTTP probes against Nginx.
- Severity weights: critical 10, high 5, medium 3, low 1. PASS earns the full weight, WARN half, FAIL none; SKIP (not testable) is excluded.
- Score = earned weight / possible weight. A category or the overall audit PASSES when its score is at least 80.0 % and no CRITICAL control failed.
- Host-level kernel settings (`kernel.*`, `fs.*`) are not namespaced: they reflect the Docker host and must be fixed there.

*Report generated automatically by `audit.py`. Re-run after every image or configuration change.*
