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
apt-mark hold '*'
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

The objective is to determine which package caused the failure.

### Step 1 — Review Package History

For Debian/Ubuntu systems:

```bash
grep "install " /var/log/dpkg.log
```

For RHEL/CentOS systems:

```bash
yum history
```

### Step 2 — Identify Recently Updated Packages

```bash
ls -lt /var/log/apt/
```

```bash
apt list --upgradable
```

### Step 3 — Check Service Status

```bash
systemctl status <service_name>
```

### Step 4 — Review Error Logs

```bash
journalctl -u <service_name>
```

```bash
tail -n 50 /var/log/syslog
```

### Step 5 — Validate Dependencies

```bash
ldd /usr/bin/<application_binary>
```

### Step 6 — Confirm Kernel Version (if kernel update)

```bash
uname -r
```

---

## 5. Rollback Procedure — Step-by-Step Recovery

Rollback restores the system to the last known stable state.

### Step 1 — Identify Previous Package Version

```bash
apt-cache policy <package_name>
```

### Step 2 — Downgrade the Package

```bash
sudo apt install <package_name>=<previous_version>
```

### Step 3 — Restart Service

```bash
systemctl restart <service_name>
```

### Step 4 — Verify Service Recovery

```bash
systemctl status <service_name>
```

```bash
curl http://localhost
```

### Step 5 — Prevent Reinstallation

```bash
apt-mark hold <package_name>
```

### Step 6 — Kernel Rollback (if required)

1. Reboot system
2. Select previous kernel from GRUB menu
3. Log into system
4. Mark new kernel as held

```bash
apt-mark hold linux-image-<version>
```

### Step 7 — Restore from Backup (Last Resort)

If rollback fails:

* Restore system snapshot
* Restore database backup
* Rebuild service environment

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

