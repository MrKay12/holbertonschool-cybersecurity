# NovaTech Patch Management Incident Response Playbook

## 1. Purpose

This playbook defines the standardized response procedure for patch-related incidents. It ensures rapid identification, containment, recovery, and documentation when a system update causes service disruption, instability, or security issues.

This document is intended for on-call engineers, system administrators, and security personnel responding to patch failures during maintenance windows or emergency updates.

---

## 2. Detection Criteria

A patch-related incident is suspected when any of the following conditions occur immediately after a package update or system patch:

### Service-Level Indicators

* Critical service fails to start after update
* Application crashes repeatedly
* Service enters degraded or unavailable state
* Unexpected service restarts
* System boot failure after kernel update

### System-Level Indicators

* High CPU or memory usage after update
* Missing dependencies or library errors
* Kernel panic or system instability
* Configuration conflicts
* Disk space exhaustion due to update

### Security Indicators

* Security service failure (firewall, IDS, authentication)
* Unauthorized configuration changes
* Failed authentication or login services
* Vulnerability scanner reports regression

### Log-Based Indicators

Common log messages indicating patch failure:

* "Failed to start"
* "Dependency error"
* "Segmentation fault"
* "Kernel panic"
* "Package configuration failed"

---

## 3. Initial Assessment — First 5 Minutes Checklist

The on-call engineer must complete the following checklist immediately upon detection.

### Step 1 — Confirm Incident

* Identify affected system hostname
* Identify impacted service or application
* Confirm time of last update
* Verify incident severity

### Step 2 — Stabilize System

* Do NOT reboot unless system is unresponsive
* Stop automated updates if running
* Prevent additional changes

Command examples:

```bash
systemctl stop unattended-upgrades
systemctl stop apt-daily.timer apt-daily-upgrade.timer
```

### Step 3 — Preserve Evidence

* Capture current system state
* Save logs before making changes
* Record running processes

Command examples:

```bash
date
hostname
uptime
ps aux > /tmp/process_snapshot.txt
journalctl -xe > /tmp/system_log_snapshot.txt
```

### Step 4 — Identify Change Window

* Determine whether update occurred during:

  * Scheduled maintenance window
  * Emergency patch deployment
  * Manual update

---

## 4. Diagnosis Steps — Identify the Bad Package

The objective is to determine exactly which package (and which version change) caused the failure.

Throughout this section, the example uses the failing service `nginx` and package `nginx`. Replace `PKG`, `SERVICE`, `OLD_VERSION` and `NEW_VERSION` with the real values.

### Step 1 — Confirm the Failing Service and Read Its Errors

```bash
systemctl --failed
systemctl status nginx
journalctl -u nginx --since "2 hours ago" --no-pager
tail -n 50 /var/log/syslog
```

Note the exact time of the first error and the error message (e.g. "Failed to start", "undefined symbol", "Segmentation fault").

### Step 2 — List Packages Changed During the Change Window

Debian/Ubuntu — apt history (who ran it, which packages, old → new versions):

```bash
grep -A6 "Start-Date" /var/log/apt/history.log | tail -n 40
zgrep -h -A6 "Start-Date" /var/log/apt/history.log.*.gz
```

Debian/Ubuntu — dpkg log (every install/upgrade/remove with timestamps):

```bash
grep -E " (install|upgrade|remove) " /var/log/dpkg.log | tail -n 30
```

RHEL/CentOS/Rocky:

```bash
yum history list
yum history info last
```

Result: a short list of candidate packages upgraded just before the first error.

### Step 3 — Correlate Packages with the Failing Service

Find which candidate packages the service actually depends on:

```bash
dpkg -S "$(command -v nginx)"
apt-cache depends nginx
ldd /usr/sbin/nginx | grep "not found"
```

Any library reported as "not found", or any candidate package that appears in the dependency list, is the prime suspect.

### Step 4 — Check Package Integrity and Configuration State

```bash
dpkg --audit
dpkg -l | grep -v "^ii"
dpkg --verify nginx
nginx -t
```

A package not in the `ii` state, a failed post-install script, or a configuration test error confirms the package.

### Step 5 — Confirm Kernel Version (if a kernel was updated)

```bash
uname -r
dpkg -l "linux-image-*" | grep "^ii"
```

If the running kernel matches the one installed in the change window and the problem is a driver/boot issue, follow the kernel rollback in Section 5, Step 7.

### Step 6 — Record the Diagnosis

Before changing anything, record in the incident ticket:

* Bad package name and NEW_VERSION (the version installed by the update)
* OLD_VERSION (last known good version, from history.log)
* Evidence (log lines, failed dependency, timestamps)

---

## 5. Rollback Procedure — Step-by-Step Recovery

Rollback restores the bad package to its last known good version, then verifies and locks it.

### Step 1 — Back Up Current State

```bash
cp -a /etc/nginx /root/nginx-config-backup-$(date +%F-%H%M)
dpkg -l > /root/packages-before-rollback.txt
```

### Step 2 — Identify the Previous (Good) Version

```bash
apt-cache policy nginx
apt list -a nginx
ls /var/cache/apt/archives/ | grep nginx
```

Use OLD_VERSION from the apt history recorded in Section 4, Step 6.

### Step 3 — Downgrade the Package

From the repository:

```bash
sudo apt install nginx=1.18.0-6ubuntu14.4
```

General form: `sudo apt install PKG=OLD_VERSION` (add `--allow-downgrades` if prompted).

From the local apt cache if the old version is no longer in the repository:

```bash
sudo dpkg -i /var/cache/apt/archives/nginx_1.18.0-6ubuntu14.4_amd64.deb
```

RHEL/CentOS equivalent:

```bash
sudo yum history undo last
sudo yum downgrade nginx
```

### Step 4 — Hold the Package to Prevent Reinstallation

```bash
sudo apt-mark hold nginx
apt-mark showhold
```

RHEL/CentOS: `sudo yum versionlock add nginx`

### Step 5 — Restart the Service

```bash
sudo systemctl daemon-reload
sudo systemctl restart nginx
```

### Step 6 — Verify Recovery

```bash
systemctl is-active nginx
systemctl status nginx
journalctl -u nginx -n 20 --no-pager
dpkg -l nginx
curl -I http://localhost
```

Success criteria: service is `active (running)`, installed version equals OLD_VERSION, no new errors in logs, and the application responds (HTTP 200).

### Step 7 — Kernel Rollback (if a kernel update caused the failure)

1. Reboot the system
2. In the GRUB menu choose "Advanced options" and select the previous kernel
3. Log in and confirm with `uname -r`
4. Hold the bad kernel and set the good one as default

```bash
sudo apt-mark hold linux-image-6.8.0-50-generic
sudo grub-set-default "1>2"
sudo update-grub
```

### Step 8 — Restore from Backup (Last Resort)

If the downgrade fails or the system is unrecoverable:

* Restore the VM/filesystem snapshot taken before the maintenance window
* Restore the database from the latest verified backup
* Rebuild the service from configuration management
* Re-run the verification checks in Step 6

### Step 9 — Release the Hold Later

Once a fixed version is published and tested in staging:

```bash
sudo apt-mark unhold nginx
sudo apt install --only-upgrade nginx
```

---

## 6. Communication Plan

Clear communication ensures coordinated response and accountability.

### Notification Timeline

| Time              | Action                                                   |
| ----------------- | -------------------------------------------------------- |
| Immediately       | Notify on-call engineer                                  |
| Within 5 minutes  | Notify system administrator                              |
| Within 15 minutes | Notify Security Operations Team                          |
| Within 30 minutes | Notify IT Operations Manager                             |
| Within 60 minutes | Notify business stakeholders if service outage continues |

### Required Notification Information

All incident notifications must include:

* Incident ID
* System name
* Affected service
* Time of detection
* Severity level
* Current status
* Actions taken

### Communication Channels

* Incident response ticketing system
* Internal messaging platform
* Email alerts
* Emergency phone escalation

---

## 7. Post-Incident Review — Lessons Learned Template

A formal review must be completed after incident resolution.

### Incident Summary

* Incident ID:
* Date and time detected:
* Date and time resolved:
* Affected systems:
* Affected services:
* Severity level:

### Root Cause Analysis

* Failed package name:
* Package version:
* Root cause description:
* Contributing factors:

### Impact Assessment

* Duration of outage:
* Number of users affected:
* Data loss (Yes/No):
* Security impact (Yes/No):

### Response Evaluation

* Detection time:
* Response time:
* Recovery time:
* Was rollback successful? (Yes/No)

### Preventive Actions

* Improve testing procedures
* Update patch validation process
* Modify monitoring rules
* Add package to blacklist
* Improve rollback automation

### Approval

* Incident responder:
* Security reviewer:
* Operations manager:
* Date:

---

## 8. Severity Classification for Patch Incidents

| Severity | Description                         | Example                             |
| -------- | ----------------------------------- | ----------------------------------- |
| Critical | Production outage or system failure | Service unavailable, system crash   |
| High     | Major service degradation           | Slow response, intermittent failure |
| Medium   | Limited functionality loss          | Minor feature failure               |
| Low      | No service impact                   | Warning or log error                |

---

## 9. Policy Compliance

Failure to follow this incident response procedure may result in:

* Extended downtime
* Security exposure
* Data integrity risks
* Compliance violations

All system administrators and on-call engineers must follow this playbook during patch-related incidents.

---

**Document Type:** Operational Runbook
**Owner:** Security Operations Team
**Version:** 1.0
**Effective Date:** [Insert Date]
**Review Frequency:** After each major incident

