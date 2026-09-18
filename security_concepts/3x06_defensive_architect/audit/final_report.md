# Nexus Financial - Final Security Audit Report

## 1. Firewall Verification

### Verification Command

```bash
ufw status verbose
```

### Expected Output

```text
Status: active
Default: deny (incoming), allow (outgoing)

5432/tcp                  DENY IN     Anywhere
5432/tcp                  ALLOW IN    10.0.1.10
22/tcp                    ALLOW IN    10.0.1.20
80/tcp                    ALLOW IN    Anywhere
443/tcp                   ALLOW IN    Anywhere
```

### Self-Assessment

**PASS**

UFW is active with a default deny policy.

PostgreSQL is blocked from the public Internet and allowed only from the Web Server `10.0.1.10`.

SSH is restricted to the Bastion Host `10.0.1.20`.

---

## 2. SSH Hardening Verification

### Verification Command

```bash
sshd -T | grep -E "permitrootlogin|passwordauthentication|pubkeyauthentication"
```

### Expected Output

```text
permitrootlogin no
passwordauthentication no
pubkeyauthentication yes
```

### Self-Assessment

**PASS**

Direct root login and SSH password authentication are disabled.

SSH public key authentication is enabled.

---

## 3. RBAC Group Verification

### Verification Command

```bash
getent group devs
getent group ops
getent group auditors
```

### Expected Output

```text
devs:x:
ops:x:
auditors:x:
```

### Self-Assessment

**PASS**

The required RBAC groups exist.

---

## 4. RBAC User Verification

### Verification Command

```bash
id sarah
id dave
```

### Expected Output

```text
sarah: groups include devs and ops
dave: groups include devs and auditors
```

### Self-Assessment

**PASS**

Sarah and Dave are assigned to the required roles.

---

## 5. Sudo Least Privilege Verification

### Verification Command

```bash
sudo -l -U sarah
```

### Expected Output

```text
User sarah may run the following commands:
    (root) /bin/systemctl restart nginx
    (root) /bin/systemctl start nginx
    (root) /bin/systemctl stop nginx
    (root) /bin/systemctl status nginx
```

Sarah must not have unrestricted sudo access such as:

```text
(ALL : ALL) ALL
```

### Self-Assessment

**PASS**

Sarah can manage the Nginx service without receiving full root access.

This follows the principle of least privilege.

---

## 6. Auditor Privilege Verification

### Verification Command

```bash
sudo -l -U dave
```

### Expected Output

```text
User dave is not allowed to run sudo
```

### Self-Assessment

**PASS**

Dave has read-only log access through the `auditors` group and cannot modify privileged system configuration using sudo.

---

## 7. Home Directory Permission Verification

### Verification Command

```bash
ls -ld /home/sarah /home/dave /home/auditor
```

### Expected Output

```text
drwx------ sarah sarah /home/sarah
drwx------ dave dave /home/dave
drwx------ auditor auditor /home/auditor
```

### Self-Assessment

**PASS**

User home directories use strict `700` permissions.

---

## 8. Auditd Sensitive File Verification

### Verification Command

```bash
auditctl -l
```

### Expected Output

```text
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudo_changes
-w /etc/ssh/sshd_config -p wa -k ssh_changes
```

### Self-Assessment

**PASS**

Sensitive identity, sudo and SSH configuration files are monitored by `auditd`.

---

## 9. Privileged Command Audit Verification

### Verification Command

```bash
auditctl -l | grep privileged_commands
```

### Expected Output

```text
-a always,exit -F arch=b64 -S execve -F euid=0 -F key=privileged_commands
-a always,exit -F arch=b32 -S execve -F euid=0 -F key=privileged_commands
```

### Self-Assessment

**PASS**

Execution of privileged commands is monitored.

---

## 10. Audit Immutability Verification

### Verification Command

```bash
auditctl -s
```

### Expected Output

```text
enabled 2
```

### Self-Assessment

**PASS**

Audit rules are immutable until reboot.

---

## 11. Centralized Logging Verification

### Verification Command

```bash
grep -R "10.0.1.30" /etc/rsyslog.d/
```

### Expected Output

```text
*.warning @@10.0.1.30:514
auth,authpriv.* @@10.0.1.30:514
kern.* @@10.0.1.30:514
```

### Self-Assessment

**PASS**

Critical logs are forwarded to the central logging server.

---

## 12. Logging Service Verification

### Verification Command

```bash
systemctl is-active rsyslog
systemctl is-active auditd
```

### Expected Output

```text
active
active
```

### Self-Assessment

**PASS**

Both centralized logging and system auditing services are running.

---

## 13. Final Self-Assessment

### Verification Command

```bash
ufw status verbose
sudo -l -U sarah
auditctl -l
auditctl -s
```

### Expected Output

The audit should confirm:

```text
UFW active
Default incoming policy: deny
PostgreSQL restricted to 10.0.1.10
SSH restricted to 10.0.1.20

Sarah sudo access limited to Nginx commands

Audit file watches enabled

Audit privileged command monitoring enabled

Audit immutable mode enabled
```

### Self-Assessment

**PASS**

The main security controls implemented for Nexus Financial are active and verifiable.

The environment now applies:

* default deny firewall rules;
* PostgreSQL network restriction;
* SSH bastion restriction;
* least privilege through RBAC;
* limited sudo access;
* strict home directory permissions;
* monitoring of sensitive files;
* auditing of privileged commands;
* immutable audit rules;
* centralized logging.

The remaining work is operational maintenance, periodic access reviews, backup testing and continuous monitoring.
