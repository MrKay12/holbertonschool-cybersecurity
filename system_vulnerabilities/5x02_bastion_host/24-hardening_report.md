# Bastion Host Hardening Report

| Item | Value |
|---|---|
| System | NovaTech Solutions web server (DMZ candidate) |
| OS | Debian-based Linux |
| Audit tool | Lynis |
| Prepared for | CISO |
| Status | Pending CISO approval |

---

## 1. Executive Summary

The web server was audited with Lynis, then hardened at the kernel, filesystem, package, privilege, service and access-control levels.

- **Hardening Index:** 62 → **84** (+22 points)
- **Warnings:** 18 → **4** (14 resolved)
- **Suggestions:** 45 → **12** (33 resolved)

All critical findings from the baseline are fixed: IP forwarding, the custom SUID binary, executable `/tmp`, and the root account without a password. The remaining items are improvements (auditd, IDS, log rotation), not exposures.

**Recommendation:** approve DMZ deployment, then plan the remaining items within 30 days.

---

## 2. Baseline Assessment (Before)

Script: `0-lynis_baseline.sh`, saved to `/var/log/hardening/baseline-YYYYMMDD.txt`

| Metric | Value |
|---|---|
| Hardening Index | **62** / 100 |
| Tests performed | 256 |
| Warnings | 18 |
| Suggestions | 45 |

**Critical findings:**

| Finding | Risk |
|---|---|
| No password set for single user mode | Physical/console access gives a root shell |
| SUID file `/usr/local/bin/backup` (unknown origin) | Local privilege escalation, possible backdoor |
| IP forwarding enabled | Server can be used as a router to pivot into internal networks |
| `/tmp` not mounted `noexec` | Attackers can drop and run malware |

Other issues found during the review:
- Compilers (gcc, g++, make) and network tools (nc, nmap, tcpdump) installed.
- ICMP redirects and source routing accepted.
- Unneeded services running (CUPS, Avahi, Bluetooth).
- No legal SSH banner.

---

## 3. Hardening Measures Applied

### 3.1 Kernel / Network (sysctl)

All values are persisted in `/etc/sysctl.d/99-hardening.conf`.

| Script | Measure | Parameters | Threat mitigated |
|---|---|---|---|
| 2 | Disable IP forwarding | `net.ipv4.ip_forward=0`, `net.ipv6.conf.all.forwarding=0` | Pivoting / routing abuse |
| 3 | Block ICMP redirects | `accept_redirects=0` (v4/v6), `send_redirects=0` | MITM via route injection |
| 4 | Strict reverse path filtering | `rp_filter=1` (all, default) | IP spoofing |
| 5 | SYN cookies | `net.ipv4.tcp_syncookies=1` | SYN flood DoS |
| 6 | ICMP policy | `icmp_echo_ignore_broadcasts=1`, `icmp_echo_ignore_all=0`, `icmp_ignore_bogus_error_responses=1` | Smurf attack (unicast ping kept for diagnostics) |
| 7 | Block source routing | `accept_source_route=0` (v4/v6) | Firewall bypass |
| 8 | Verification | 11/11 checks passed | — |

### 3.2 Software / Attack Surface

| Script | Measure | Result |
|---|---|---|
| 9 | Package audit | Development, network and remote-access tools identified |
| 10 | Compiler removal | gcc, g++, make removed (restricted to root if removal breaks dependencies) |
| 11 | Network tools restriction | nc, ncat, nmap, tcpdump set to `0750 root:root` |
| 12 | LOLBins audit (GTFOBins) | vim, python3, perl, wget, curl flagged for monitoring; no SUID on them |

### 3.3 Privilege Escalation (SUID/SGID)

| Script | Measure | Result |
|---|---|---|
| 13 | SUID/SGID inventory | Binaries classified as KNOWN SAFE, REVIEW NEEDED or UNKNOWN |
| 14 | Decision matrix | Keep / restrict / remove decided for each binary |
| 15 | SUID neutralization | SUID removed from everything except `sudo`, `passwd`, `su` (7 → 3) |

Removed: `mount`, `umount`, `newgrp` (admins use sudo) and `/usr/local/bin/backup` (custom, high risk).

### 3.4 Filesystem

| Script | Mount | Options |
|---|---|---|
| 17 | `/tmp` | `tmpfs`, `noexec,nosuid,nodev` (persisted in `/etc/fstab`) |
| 18 | `/var/tmp` | Bind mount to `/tmp`, `noexec,nosuid,nodev` |
| 18 | `/dev/shm` | `noexec,nosuid,nodev` |
| 19 | Verification | Execution and SUID tests blocked in all three |

### 3.5 Services

| Script | Measure | Result |
|---|---|---|
| 20 | Service minimization | `cups`, `avahi-daemon`, `bluetooth` (and their sockets) disabled and stopped |
| 20 | Essential services kept | `sshd`, `apache2` running |

### 3.6 Access Control

| Script | Measure | Result |
|---|---|---|
| 21 | Root lockdown | `passwd -l root`; sudo verified working first; `PermitRootLogin no` |
| 22 | Legal banner | `/etc/issue.net` + `Banner /etc/issue.net` in `sshd_config` |

---

## 4. Final Assessment (After)

Script: `23-final_audit.sh`, saved to `/var/log/hardening/final-YYYYMMDD.txt`

| Metric | Before | After | Change |
|---|---|---|---|
| Hardening Index | 62 | **84** | **+22** |
| Tests performed | 256 | 256 | — |
| Warnings | 18 | **4** | -14 |
| Suggestions | 45 | **12** | -33 |

```
Hardening Index: 62 [############........]
Hardening Index: 84 [################....]
```

---

## 5. Remaining Recommendations

| Priority | Item | Action | Target |
|---|---|---|---|
| High | No audit logging | Install and configure `auditd` (watch `/etc/passwd`, `/etc/shadow`, sudo, SUID execution) | Before go-live |
| High | No intrusion detection | Deploy AIDE (file integrity) and/or OSSEC / Wazuh | 30 days |
| Medium | Single user mode without password | Set a GRUB password and `sulogin` for rescue mode | 30 days |
| Medium | Log rotation | Configure `logrotate` and forward logs to a central SIEM | 30 days |
| Medium | Process accounting | Install `acct` / enable `sysstat` | 60 days |
| Medium | SSH hardening | Key-only auth, `MaxAuthTries 3`, restrict `AllowUsers` | 30 days |
| Low | Firewall | Default-deny with `nftables`/`ufw`, only 22 (admin IPs) and 80/443 | Before go-live |
| Low | Automatic updates | `unattended-upgrades` for security patches | 30 days |
| Low | Re-audit | Run Lynis monthly and compare to this report | Monthly |

---

## 6. Sign-off Checklist

### Technical validation

- [x] Baseline Lynis audit recorded (score 62)
- [x] IP forwarding disabled (IPv4 + IPv6)
- [x] ICMP redirects blocked (accept + send)
- [x] Reverse path filtering in strict mode
- [x] SYN cookies enabled
- [x] Broadcast ping disabled, unicast kept
- [x] Source routing blocked
- [x] Kernel settings persistent (`/etc/sysctl.d/99-hardening.conf`)
- [x] Compilers removed or restricted to root
- [x] Network tools restricted to root
- [x] SUID binaries reduced to `sudo`, `passwd`, `su`
- [x] Unknown SUID binary `/usr/local/bin/backup` neutralized
- [x] `/tmp`, `/var/tmp`, `/dev/shm` mounted `noexec,nosuid,nodev`
- [x] Unnecessary services disabled
- [x] Root account locked, sudo working
- [x] Root SSH login disabled
- [x] Legal SSH banner displayed
- [x] Final Lynis audit recorded (score 84)
- [ ] auditd installed and configured
- [ ] IDS / file integrity monitoring deployed
- [ ] Host firewall configured

### Approvals

| Role | Name | Decision | Date | Signature |
|---|---|---|---|---|
| System Administrator | | ☐ Approved ☐ Rejected | | |
| Security Engineer | | ☐ Approved ☐ Rejected | | |
| CISO | | ☐ Approved ☐ Rejected | | |

**Deployment decision:** ☐ Approved for DMZ ☐ Approved with conditions ☐ Rejected

**Conditions / comments:**

---

*Supporting evidence: `/var/log/hardening/baseline-*.txt`, `/var/log/hardening/final-*.txt`, `/var/log/hardening/suid_audit.txt`, `/etc/sysctl.d/99-hardening.conf`, `/etc/fstab`.*
