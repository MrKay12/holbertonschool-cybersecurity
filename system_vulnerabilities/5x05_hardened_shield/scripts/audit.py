#!/usr/bin/env python3
"""audit.py - NovaTech Hardened Shield security audit tool.

Audits the running container from the inside across five categories:

    1. Kernel hardening     network sysctls (5x02) and host kernel settings
    2. Filesystem security  mounts, SUID/SGID, permissions, read-only root
    3. Identity security    PAM password policy, lockout, aging, root (5x03)
    4. Service security     effective sshd config, nginx exposure, ports
    5. Container security   capabilities, seccomp, no-new-privileges,
                            resource limits, secrets, docker socket (5x04)

Scoring
    Every check has a severity weight: critical 10, high 5, medium 3, low 1.
    PASS earns the full weight, WARN half, FAIL nothing; SKIP (not testable,
    e.g. not root) is left out. Category and overall scores are
    earned / possible weight, in percent.
    Status: PASS when the score reaches the threshold (default 80 %) and no
    CRITICAL check failed; otherwise FAIL.

Usage
    audit.py                               console report
    audit.py -o audit_result.md            + formal Markdown report
    audit.py -o -                          Markdown on stdout only
    audit.py --json result.json            + JSON (CI pipelines)
    audit.py --category identity,service   only some categories
    audit.py --threshold 90 --no-color --quiet

    In the container (read-only root FS):
        docker exec shield audit.py -o - > audit_result.md

Exit codes
    0  overall PASS
    1  overall FAIL
    2  usage / output error

Run as root (docker exec default) for full coverage.
"""

import argparse
import datetime
import glob
import grp
import http.client
import json
import os
import pwd
import re
import socket
import stat
import subprocess
import sys
from dataclasses import asdict, dataclass, field

VERSION = "1.0.0"

PASS, WARN, FAIL, SKIP = "PASS", "WARN", "FAIL", "SKIP"
CRITICAL, HIGH, MEDIUM, LOW = "critical", "high", "medium", "low"
WEIGHT = {CRITICAL: 10, HIGH: 5, MEDIUM: 3, LOW: 1}
CREDIT = {PASS: 1.0, WARN: 0.5, FAIL: 0.0}
SEV_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}

CATEGORIES = {
    "kernel": ("KRN", "Kernel hardening"),
    "filesystem": ("FS", "Filesystem security"),
    "identity": ("IDN", "Identity security"),
    "service": ("SVC", "Service security"),
    "container": ("CTR", "Container security"),
}

WEB_PORT = int(os.environ.get("WEB_PORT", "8080"))
SSH_PORT = int(os.environ.get("SSH_PORT", "22"))
EXPECTED_PORTS = {WEB_PORT, SSH_PORT}
ADMIN = os.environ.get("SSH_ADMIN_USER", "sysadmin")
APP_USER = "appuser"


# =============================================================================
# Result model
# =============================================================================
@dataclass
class Check:
    id: str
    category: str
    title: str
    status: str
    severity: str
    detail: str = ""
    remediation: str = ""


@dataclass
class Audit:
    checks: list = field(default_factory=list)
    counters: dict = field(default_factory=dict)

    def add(self, cat, title, status, severity, detail="", remediation=""):
        prefix = CATEGORIES[cat][0]
        self.counters[cat] = self.counters.get(cat, 0) + 1
        cid = f"{prefix}-{self.counters[cat]:02d}"
        self.checks.append(Check(cid, cat, title, status, severity,
                                 str(detail), remediation if status != PASS else ""))

    def expect(self, cat, title, ok, severity, detail="", remediation="", warn=False):
        """PASS if ok, else FAIL (or WARN when warn=True)."""
        self.add(cat, title, PASS if ok else (WARN if warn else FAIL),
                 severity, detail, remediation)


A = Audit()


# =============================================================================
# Helpers
# =============================================================================
IS_ROOT = os.geteuid() == 0


def read(path):
    """File content; None if permission denied, '' if missing."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except PermissionError:
        return None
    except OSError:
        return ""


def lines(text):
    return [l.strip() for l in (text or "").splitlines()
            if l.strip() and not l.strip().startswith("#")]


def kv(text, key, sep="="):
    """First active value of key in a 'key = value' or 'Key value' file."""
    for line in lines(text):
        if sep == "=":
            k, eq, v = line.partition("=")
            if eq and k.strip().lower() == key.lower():
                return v.strip()
        else:
            parts = line.split(None, 1)
            if parts and parts[0].lower() == key.lower():
                return parts[1].strip() if len(parts) > 1 else ""
    return None


def flag(text, word):
    return any(l.split()[0] == word for l in lines(text) if l.split())


def to_int(value, default=None):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def sysctl(key):
    return (read("/proc/sys/" + key.replace(".", "/")) or "").strip()


def mounts():
    out = {}
    for line in (read("/proc/mounts") or "").splitlines():
        parts = line.split()
        if len(parts) >= 4:
            out[parts[1]] = parts[3].split(",")   # last mount wins
    return out


def proc_status(pid, fieldname):
    m = re.search(rf"^{fieldname}:\s*(.*)$", read(f"/proc/{pid}/status") or "", re.M)
    return m.group(1).strip() if m else None


def processes():
    """[(pid, comm, uid)]"""
    out = []
    for d in glob.glob("/proc/[0-9]*"):
        pid = d.rsplit("/", 1)[1]
        comm = (read(f"{d}/comm") or "").strip()
        uid = proc_status(pid, "Uid")
        if comm and uid:
            out.append((int(pid), comm, int(uid.split()[0])))
    return out


def which(cmd):
    for d in "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".split(":"):
        if os.access(os.path.join(d, cmd), os.X_OK):
            return os.path.join(d, cmd)
    return None


def walk_files(roots=("/",), skip=("/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp")):
    """Regular files and dirs on the root filesystem only (like find -xdev)."""
    try:
        root_dev = os.lstat("/").st_dev
    except OSError:
        return
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames
                           if os.path.join(dirpath, d) not in skip
                           and _same_dev(os.path.join(dirpath, d), root_dev)]
            for name in filenames + dirnames:
                p = os.path.join(dirpath, name)
                try:
                    yield p, os.lstat(p)
                except OSError:
                    continue


def _same_dev(path, dev):
    try:
        return os.lstat(path).st_dev == dev
    except OSError:
        return False


def mode_of(path):
    try:
        st = os.stat(path)
        return st.st_mode & 0o7777, st.st_uid, st.st_gid
    except OSError:
        return None


def owner(uid, gid):
    try:
        u = pwd.getpwuid(uid).pw_name
    except KeyError:
        u = str(uid)
    try:
        g = grp.getgrgid(gid).gr_name
    except KeyError:
        g = str(gid)
    return f"{u}:{g}"


def http_request(method, path, port=WEB_PORT, timeout=3):
    """(status, headers dict, body) or (None, {}, error)."""
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        conn.request(method, path, headers={"User-Agent": "hardened-shield-audit"})
        resp = conn.getresponse()
        body = resp.read(4096).decode(errors="replace")
        headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
        return resp.status, headers, body
    except (OSError, http.client.HTTPException) as exc:
        return None, {}, str(exc)


def listening_ports():
    """TCP ports in LISTEN state, from /proc/net/tcp{,6}."""
    ports = set()
    for f in ("/proc/net/tcp", "/proc/net/tcp6"):
        for line in (read(f) or "").splitlines()[1:]:
            parts = line.split()
            if len(parts) > 3 and parts[3] == "0A":
                ports.add(int(parts[1].rsplit(":", 1)[1], 16))
    return ports


def sshd_effective():
    """(dict lowercase key -> value, source). Uses 'sshd -T' when possible."""
    args = []
    argfile = read("/run/hardened-shield/sshd.args")
    if argfile:
        args = [a for a in argfile.splitlines() if a]
    sshd = which("sshd")
    if IS_ROOT and sshd:
        try:
            out = subprocess.run(
                [sshd, "-T", "-C", f"user={ADMIN},host=audit,addr=127.0.0.1"] + args,
                capture_output=True, text=True, timeout=10, check=True).stdout
            cfg = {}
            for line in out.splitlines():
                k, _, v = line.partition(" ")
                cfg.setdefault(k.lower(), v.strip())
            return cfg, "sshd -T (effective)"
        except (OSError, subprocess.SubprocessError):
            pass
    text = read("/etc/ssh/sshd_config")
    if text is None:
        return None, "unreadable"
    cfg = {}
    for line in lines(text):
        if line.lower().startswith("match "):
            break
        parts = line.split(None, 1)
        if len(parts) == 2:
            cfg.setdefault(parts[0].lower(), parts[1].strip())
    # Unset keys take the OpenSSH default, as "sshd -T" would report.
    for key, value in SSHD_DEFAULTS.items():
        cfg.setdefault(key, value)
    return cfg, "sshd_config + OpenSSH defaults"


SSHD_DEFAULTS = {
    "permitrootlogin": "prohibit-password", "passwordauthentication": "yes",
    "permitemptypasswords": "no", "pubkeyauthentication": "yes", "x11forwarding": "no",
    "allowtcpforwarding": "yes", "allowagentforwarding": "yes", "permittunnel": "no",
    "permituserenvironment": "no", "hostbasedauthentication": "no", "loglevel": "INFO",
    "maxauthtries": "6", "logingracetime": "120", "clientaliveinterval": "0", "banner": "none",
}


# =============================================================================
# 1. Kernel hardening
# =============================================================================
NET_SYSCTLS = [
    ("net.ipv4.ip_forward", "0", HIGH, "IP forwarding disabled (no routing between networks)"),
    ("net.ipv4.conf.all.accept_redirects", "0", MEDIUM, "ICMP redirects ignored (all)"),
    ("net.ipv4.conf.default.accept_redirects", "0", MEDIUM, "ICMP redirects ignored (default)"),
    ("net.ipv4.conf.all.secure_redirects", "0", LOW, "Secure ICMP redirects ignored"),
    ("net.ipv4.conf.all.send_redirects", "0", MEDIUM, "ICMP redirects not sent (all)"),
    ("net.ipv4.conf.default.send_redirects", "0", MEDIUM, "ICMP redirects not sent (default)"),
    ("net.ipv4.conf.all.rp_filter", "1", MEDIUM, "Reverse-path filtering (anti-spoofing, all)"),
    ("net.ipv4.conf.default.rp_filter", "1", MEDIUM, "Reverse-path filtering (default)"),
    ("net.ipv4.conf.all.accept_source_route", "0", HIGH, "Source-routed packets rejected (all)"),
    ("net.ipv4.conf.default.accept_source_route", "0", HIGH, "Source-routed packets rejected (default)"),
    ("net.ipv4.conf.all.log_martians", "1", LOW, "Martian packets logged"),
    ("net.ipv4.tcp_syncookies", "1", HIGH, "TCP SYN cookies (SYN flood protection)"),
    ("net.ipv4.icmp_echo_ignore_broadcasts", "1", MEDIUM, "Broadcast ICMP ignored (smurf)"),
    ("net.ipv4.icmp_ignore_bogus_error_responses", "1", LOW, "Bogus ICMP errors ignored"),
]

HOST_SYSCTLS = [
    ("kernel.randomize_va_space", "2", HIGH, "Full ASLR"),
    ("kernel.kptr_restrict", ("1", "2"), MEDIUM, "Kernel pointers hidden"),
    ("kernel.dmesg_restrict", "1", LOW, "dmesg restricted to privileged users"),
    ("fs.protected_symlinks", "1", MEDIUM, "Protected symlinks"),
    ("fs.protected_hardlinks", "1", MEDIUM, "Protected hardlinks"),
    ("fs.suid_dumpable", "0", MEDIUM, "No core dumps of SUID programs"),
]


def audit_kernel():
    c = "kernel"
    for key, want, sev, title in NET_SYSCTLS:
        have = sysctl(key)
        if not have:
            A.add(c, title, SKIP, sev, f"{key} not available")
            continue
        A.expect(c, title, have == want, sev, f"{key} = {have}",
                 f"docker run --sysctl {key}={want} (compose: sysctls)")
    # Not namespaced: they belong to the Docker host and protect every container.
    for key, want, sev, title in HOST_SYSCTLS:
        have = sysctl(key)
        wanted = want if isinstance(want, tuple) else (want,)
        if not have:
            A.add(c, f"{title} (host)", SKIP, sev, f"{key} not readable")
            continue
        A.expect(c, f"{title} (host)", have in wanted, sev, f"{key} = {have}",
                 f"on the Docker host: sysctl -w {key}={wanted[0]} (/etc/sysctl.d/)")


# =============================================================================
# 2. Filesystem security
# =============================================================================
def audit_filesystem():
    c = "filesystem"
    mnt = mounts()

    A.expect(c, "Root filesystem mounted read-only", "ro" in mnt.get("/", []), HIGH,
             ",".join(mnt.get("/", [])[:3]), "docker run --read-only (compose: read_only: true)")

    for mp, sev in (("/tmp", HIGH), ("/dev/shm", MEDIUM)):
        opts = mnt.get(mp)
        if opts is None:
            A.add(c, f"{mp} is a separate mount", FAIL, sev, "not mounted",
                  f"--tmpfs {mp}:rw,noexec,nosuid,nodev")
            continue
        missing = [o for o in ("noexec", "nosuid", "nodev") if o not in opts]
        A.expect(c, f"{mp} mounted noexec,nosuid,nodev", not missing, sev,
                 "missing: " + ",".join(missing) if missing else "noexec,nosuid,nodev",
                 f"--tmpfs {mp}:rw,noexec,nosuid,nodev")

    suid, ww_files, ww_dirs, unowned = [], [], [], []
    uids = {p.pw_uid for p in pwd.getpwall()}
    gids = {g.gr_gid for g in grp.getgrall()}
    for path, st in walk_files():
        if stat.S_ISREG(st.st_mode):
            if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                suid.append(path)
            if st.st_mode & stat.S_IWOTH:
                ww_files.append(path)
        elif stat.S_ISDIR(st.st_mode):
            if st.st_mode & stat.S_IWOTH and not st.st_mode & stat.S_ISVTX:
                ww_dirs.append(path)
        if st.st_uid not in uids or st.st_gid not in gids:
            unowned.append(path)

    A.expect(c, "No SUID/SGID binaries", not suid, HIGH,
             ", ".join(suid[:8]) or "0 found", "init-hardening.sh --build (chmod u-s,g-s)")
    A.expect(c, "No world-writable files", not ww_files, MEDIUM,
             ", ".join(ww_files[:8]) or "0 found", "chmod o-w <file>")
    A.expect(c, "World-writable directories have the sticky bit", not ww_dirs, MEDIUM,
             ", ".join(ww_dirs[:8]) or "0 found", "chmod +t <dir>")
    A.expect(c, "No unowned files", not unowned, LOW,
             ", ".join(unowned[:8]) or "0 found", "chown root:root <file>")

    for path, want_owner, max_mode, sev in (
            ("/etc/shadow", ("root:shadow", "root:root"), 0o640, HIGH),
            ("/etc/gshadow", ("root:shadow", "root:root"), 0o640, MEDIUM),
            ("/etc/passwd", ("root:root",), 0o644, MEDIUM),
            ("/etc/group", ("root:root",), 0o644, LOW),
            ("/etc/ssh/sshd_config", ("root:root",), 0o600, MEDIUM),
            ("/root", ("root:root",), 0o700, MEDIUM)):
        info = mode_of(path)
        if info is None:
            A.add(c, f"{path} permissions", SKIP, sev, "missing")
            continue
        mode, uid, gid = info
        own = owner(uid, gid)
        A.expect(c, f"{path} {want_owner[0]} {oct(max_mode)[2:]} or stricter",
                 own in want_owner and not mode & ~max_mode & 0o7777, sev,
                 f"{own} {oct(mode)[2:]}", f"chown {want_owner[0]} {path}; chmod {oct(max_mode)[2:]} {path}")

    # Web content must not be writable by the web server account.
    writable = []
    try:
        app = pwd.getpwnam(APP_USER)
        for path, st in walk_files(roots=("/var/www",)):
            if st.st_uid == app.pw_uid or st.st_mode & stat.S_IWOTH or \
                    (st.st_gid == app.pw_gid and st.st_mode & stat.S_IWGRP):
                writable.append(path)
        A.expect(c, f"Web content not writable by {APP_USER}", not writable, HIGH,
                 ", ".join(writable[:5]) or "root-owned, read-only for appuser",
                 "chown -R root:appuser /var/www/html; dirs 0750, files 0640")
    except KeyError:
        A.add(c, f"Web content not writable by {APP_USER}", SKIP, HIGH, f"{APP_USER} missing")

    limits = read("/etc/security/limits.d/99-hardening.conf") or ""
    A.expect(c, "Core dumps disabled", bool(re.search(r"\*\s+hard\s+core\s+0", limits)), LOW,
             "limits.d hard core 0" if limits else "no limit", "* hard core 0 in limits.d")
    umask = kv(read("/etc/login.defs"), "UMASK", sep=" ")
    try:
        umask_ok = umask is not None and (int(umask, 8) & 0o027) == 0o027
    except ValueError:
        umask_ok = False
    A.expect(c, "Default umask 027 or stricter", umask_ok, LOW,
             f"UMASK {umask or 'unset'}", "UMASK 027 in /etc/login.defs")


# =============================================================================
# 3. Identity security
# =============================================================================
def audit_identity():
    c = "identity"
    pwq = read("/etc/security/pwquality.conf") or ""
    minlen = to_int(kv(pwq, "minlen"), 0)
    A.expect(c, "Password minimum length >= 12", minlen >= 12, HIGH, f"minlen = {minlen}",
             "minlen = 12 in /etc/security/pwquality.conf")
    classes = [k for k in ("dcredit", "ucredit", "lcredit", "ocredit")
               if to_int(kv(pwq, k), 0) <= -1]
    A.expect(c, "Password requires digit, upper, lower, special", len(classes) == 4, MEDIUM,
             f"required: {', '.join(classes) or 'none'}", "d/u/l/ocredit = -1")
    A.expect(c, "Password complexity enforced for root", flag(pwq, "enforce_for_root"), LOW,
             "enforce_for_root" if flag(pwq, "enforce_for_root") else "absent", "add enforce_for_root")

    cpw = read("/etc/pam.d/common-password") or ""
    A.expect(c, "pam_pwquality active", "pam_pwquality.so" in "\n".join(lines(cpw)), HIGH,
             "common-password", "pam-auth-update --enable pwquality")
    m = re.search(r"pam_pwhistory\.so.*remember=(\d+)", "\n".join(lines(cpw)))
    A.expect(c, "Password history (last 5 refused)", bool(m) and int(m.group(1)) >= 5, MEDIUM,
             f"remember={m.group(1)}" if m else "pam_pwhistory absent",
             "pam_pwhistory.so remember=5 before pam_unix")

    cauth = "\n".join(lines(read("/etc/pam.d/common-auth")))
    fl_ok = all(s in cauth for s in ("pam_faillock.so preauth", "pam_faillock.so authfail"))
    A.expect(c, "Account lockout (pam_faillock) active", fl_ok, HIGH,
             "preauth + authfail" if fl_ok else "missing", "pam-auth-update --enable faillock faillock_notify")
    fl = read("/etc/security/faillock.conf") or ""
    deny, unlock = to_int(kv(fl, "deny")), kv(fl, "unlock_time")
    A.expect(c, "Lockout after <= 5 failures", deny is not None and 0 < deny <= 5, MEDIUM,
             f"deny = {deny}", "deny = 5 in faillock.conf")
    A.expect(c, "Lockout duration >= 15 min",
             unlock is not None and (unlock == "never" or to_int(unlock, 0) >= 900 or unlock == "0"),
             MEDIUM, f"unlock_time = {unlock}", "unlock_time = 900")
    A.expect(c, "Lockout applies to root", flag(fl, "even_deny_root"), LOW,
             "even_deny_root" if flag(fl, "even_deny_root") else "absent", "add even_deny_root")

    defs = read("/etc/login.defs") or ""
    mx, mn = to_int(kv(defs, "PASS_MAX_DAYS", " "), 99999), to_int(kv(defs, "PASS_MIN_DAYS", " "), 0)
    A.expect(c, "Password maximum age <= 90 days", mx <= 90, MEDIUM, f"PASS_MAX_DAYS {mx}", "PASS_MAX_DAYS 90")
    A.expect(c, "Password minimum age >= 1 day", mn >= 1, LOW, f"PASS_MIN_DAYS {mn}", "PASS_MIN_DAYS 1")
    enc = (kv(defs, "ENCRYPT_METHOD", " ") or "").upper()
    A.expect(c, "Strong password hashing", enc in ("YESCRYPT", "SHA512"), MEDIUM,
             f"ENCRYPT_METHOD {enc or 'unset'}", "ENCRYPT_METHOD YESCRYPT")

    users = pwd.getpwall()
    uid0 = [u.pw_name for u in users if u.pw_uid == 0]
    A.expect(c, "Only root has UID 0", uid0 == ["root"], CRITICAL, ", ".join(uid0),
             "remove or renumber the extra UID 0 accounts")
    bad_shell = [u.pw_name for u in users if 0 < u.pw_uid < 1000
                 and u.pw_shell not in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/bin/sync")]
    A.expect(c, "System accounts cannot log in", not bad_shell, MEDIUM,
             ", ".join(bad_shell) or "all nologin", "usermod -s /usr/sbin/nologin <user>")
    try:
        shell = pwd.getpwnam(APP_USER).pw_shell
        A.expect(c, f"{APP_USER} (web) has no login shell", shell.endswith("nologin"), HIGH,
                 shell, f"usermod -s /usr/sbin/nologin {APP_USER}")
    except KeyError:
        A.add(c, f"{APP_USER} (web) has no login shell", FAIL, HIGH, "account missing")

    shadow = read("/etc/shadow")
    if shadow is None:
        for t, s in (("Root password locked", CRITICAL), ("No account with an empty password", CRITICAL),
                     (f"{ADMIN} is key-only (no password)", MEDIUM)):
            A.add(c, t, SKIP, s, "needs root")
    else:
        sh = {l.split(":")[0]: l.split(":")[1] for l in shadow.splitlines() if l.count(":") >= 2}
        root = sh.get("root", "")
        A.expect(c, "Root password locked", root.startswith(("!", "*")), CRITICAL,
                 "locked" if root.startswith(("!", "*")) else "usable hash", "passwd -l root")
        empty = [u for u, h in sh.items() if h == ""]
        A.expect(c, "No account with an empty password", not empty, CRITICAL,
                 ", ".join(empty) or "none", "passwd -l <user>")
        adm = sh.get(ADMIN)
        A.expect(c, f"{ADMIN} is key-only (no password)", adm in ("*", "!", "!*"), MEDIUM,
                 "no usable password" if adm in ("*", "!", "!*") else "has a password hash",
                 f"usermod -p '*' {ADMIN}")

    su = "\n".join(lines(read("/etc/pam.d/su")))
    A.expect(c, "su restricted (pam_wheel)", "pam_wheel.so" in su, LOW,
             "pam_wheel" if "pam_wheel.so" in su else "unrestricted",
             "auth required pam_wheel.so use_uid group=sugroup")
    tmout = read("/etc/profile.d/99-tmout.sh") or ""
    m = re.search(r"TMOUT=(\d+)", tmout)
    A.expect(c, "Idle shell timeout <= 15 min", bool(m) and 0 < int(m.group(1)) <= 900, LOW,
             f"TMOUT={m.group(1)}" if m else "unset", "readonly TMOUT=900 in /etc/profile.d")


# =============================================================================
# 4. Service security
# =============================================================================
WEAK_CRYPTO = re.compile(r"(cbc|3des|arcfour|blowfish|hmac-md5|hmac-sha1(?!-etm)|umac-64[^-]|"
                         r"diffie-hellman-group1-|diffie-hellman-group14-sha1|group-exchange-sha1)", re.I)


def audit_service():
    c = "service"
    procs = processes()

    # --- SSH ---------------------------------------------------------------
    sshd_procs = [p for p in procs if p[1] == "sshd"]
    A.expect(c, "SSH server running", bool(sshd_procs), HIGH,
             f"{len(sshd_procs)} sshd process(es)", "init-services.sh --start")
    cfg, src = sshd_effective()
    if cfg is None:
        A.add(c, "sshd configuration", SKIP, HIGH, "sshd_config unreadable (needs root)")
    else:
        def ssh(key, want, sev, title, fix=None):
            have = cfg.get(key.lower())
            A.expect(c, title, (have or "").lower() == want.lower(), sev,
                     f"{key} {have} [{src}]", fix or f"{key} {want} in sshd_config")
        ssh("PermitRootLogin", "no", CRITICAL, "SSH: root login refused")
        ssh("PasswordAuthentication", "no", CRITICAL, "SSH: password authentication disabled")
        ssh("PermitEmptyPasswords", "no", CRITICAL, "SSH: empty passwords refused")
        ssh("PubkeyAuthentication", "yes", HIGH, "SSH: public key authentication")
        ssh("X11Forwarding", "no", MEDIUM, "SSH: X11 forwarding disabled")
        ssh("AllowTcpForwarding", "no", MEDIUM, "SSH: TCP forwarding disabled (no pivoting)")
        ssh("AllowAgentForwarding", "no", LOW, "SSH: agent forwarding disabled")
        ssh("PermitTunnel", "no", MEDIUM, "SSH: tunnels disabled")
        ssh("PermitUserEnvironment", "no", MEDIUM, "SSH: user environment ignored")
        ssh("HostbasedAuthentication", "no", MEDIUM, "SSH: host-based authentication disabled")
        ssh("LogLevel", "VERBOSE", LOW, "SSH: verbose logging (key fingerprints)")
        tries = to_int(cfg.get("maxauthtries"), 6)
        A.expect(c, "SSH: MaxAuthTries <= 3", tries <= 3, MEDIUM, f"MaxAuthTries {tries}", "MaxAuthTries 3")
        grace = to_int(cfg.get("logingracetime"), 120)
        A.expect(c, "SSH: LoginGraceTime <= 60 s", 0 < grace <= 60, LOW, f"LoginGraceTime {grace}",
                 "LoginGraceTime 30")
        alive = to_int(cfg.get("clientaliveinterval"), 0)
        A.expect(c, "SSH: idle sessions closed", 0 < alive <= 900, LOW,
                 f"ClientAliveInterval {alive}", "ClientAliveInterval 300 / ClientAliveCountMax 2")
        groups = cfg.get("allowgroups") or cfg.get("allowusers")
        A.expect(c, "SSH: login restricted to a group/user list", bool(groups), HIGH,
                 f"AllowGroups {groups}", "AllowGroups sshusers")
        banner = cfg.get("banner")
        A.expect(c, "SSH: legal banner displayed", bool(banner) and banner != "none", LOW,
                 f"Banner {banner}", "Banner /etc/issue.net")
        weak = sorted({w for k in ("ciphers", "macs", "kexalgorithms")
                       for w in (cfg.get(k) or "").split(",") if WEAK_CRYPTO.search(w)})
        A.expect(c, "SSH: no weak ciphers, MACs or key exchange", not weak and bool(cfg.get("ciphers")),
                 HIGH, ", ".join(weak) or "modern algorithms only",
                 "restrict Ciphers/MACs/KexAlgorithms to AEAD/ETM/curve25519")
    baked = glob.glob("/etc/ssh/ssh_host_*_key")
    A.expect(c, "SSH: no host key baked into the image", not baked, HIGH,
             ", ".join(baked) or "generated at runtime", "delete /etc/ssh/ssh_host_* at build")
    keydirs = glob.glob("/var/lib/ssh-hostkeys/ssh_host_*_key") + glob.glob("/run/ssh-hostkeys/ssh_host_*_key")
    loose = [k for k in keydirs if (mode_of(k) or (0o777,))[0] & 0o077]
    if keydirs:
        A.expect(c, "SSH: host private keys mode 600", not loose, HIGH,
                 ", ".join(loose) or f"{len(keydirs)} key(s) 600", "chmod 600 <key>")

    # --- Web ---------------------------------------------------------------
    nginx = [p for p in procs if p[1] == "nginx"]
    A.expect(c, "Web server running", bool(nginx), HIGH, f"{len(nginx)} nginx process(es)",
             "init-services.sh --start")
    if nginx:
        root_n = [str(p[0]) for p in nginx if p[2] == 0]
        A.expect(c, "Web server runs without root (master + workers)", not root_n, CRITICAL,
                 "pids as root: " + ", ".join(root_n) if root_n else
                 f"uids {sorted({p[2] for p in nginx})}", f"run nginx as {APP_USER} (setpriv)")
    status, headers, body = http_request("GET", "/health")
    A.expect(c, "Web health endpoint answers 200", status == 200 and "OK" in body, HIGH,
             f"HTTP {status}" if status else body, "check nginx with init-services.sh --status")
    if status is not None:
        server = headers.get("server", "")
        A.expect(c, "Web server version hidden", not re.search(r"\d", server), MEDIUM,
                 f"Server: {server}", "server_tokens off;")
        s2, h2, _ = http_request("GET", "/")
        missing = [h for h in ("x-frame-options", "x-content-type-options",
                               "content-security-policy", "referrer-policy") if h not in h2]
        A.expect(c, "Web security headers present", not missing, MEDIUM,
                 "missing: " + ", ".join(missing) if missing else "XFO, XCTO, CSP, Referrer-Policy",
                 "add_header ... always; in nginx.conf")
        s3, _, _ = http_request("GET", "/.git/config")
        A.expect(c, "Web: hidden files not served", s3 in (403, 404), MEDIUM, f"/.git/config -> HTTP {s3}",
                 "location ~ /\\. { deny all; }")
        bad = [f"{m} {s}" for m in ("TRACE", "PUT", "DELETE")
               for s in [http_request(m, "/")[0]] if s not in (403, 405, 501)]
        A.expect(c, "Web: only GET/HEAD allowed", not bad, MEDIUM,
                 ", ".join(bad) or "TRACE/PUT/DELETE refused", "limit_except GET HEAD { deny all; }")

    # --- Exposure ----------------------------------------------------------
    ports = listening_ports()
    extra = sorted(ports - EXPECTED_PORTS)
    A.expect(c, f"Only expected ports listening ({', '.join(map(str, sorted(EXPECTED_PORTS)))})",
             not extra, HIGH, f"listening: {sorted(ports)}", "stop the service bound to the extra port")
    forbidden = {"cron", "atd", "rsyslogd", "inetd", "xinetd", "telnetd", "vsftpd", "avahi-daemon",
                 "cupsd", "rpcbind", "smbd", "nmbd", "snmpd", "dhcpd", "named", "exim4", "master", "dnsmasq"}
    running = sorted({p[1] for p in procs} & forbidden)
    A.expect(c, "No unneeded daemons running", not running, MEDIUM,
             ", ".join(running) or "none", "remove the package (init-hardening.sh)")
    tools = [t for t in ("gcc", "cc", "make", "nc", "netcat", "ncat", "nmap", "socat", "tcpdump", "telnet")
             if which(t)]
    A.expect(c, "No compilers or network attack tools", not tools, MEDIUM,
             ", ".join(tools) or "none", "purge them (init-hardening.sh --build)")
    f2b = [p for p in procs if p[1] == "fail2ban-server"]
    A.expect(c, "Brute-force banning (fail2ban) running", bool(f2b), LOW,
             "running" if f2b else "not started (needs NET_ADMIN); faillock + MaxAuthTries still apply",
             "cap_add: NET_ADMIN, NET_RAW to enable fail2ban", warn=True)


# =============================================================================
# 5. Container security
# =============================================================================
CAPS = {0: "CHOWN", 1: "DAC_OVERRIDE", 2: "DAC_READ_SEARCH", 3: "FOWNER", 4: "FSETID", 5: "KILL",
        6: "SETGID", 7: "SETUID", 8: "SETPCAP", 9: "LINUX_IMMUTABLE", 10: "NET_BIND_SERVICE",
        11: "NET_BROADCAST", 12: "NET_ADMIN", 13: "NET_RAW", 14: "IPC_LOCK", 15: "IPC_OWNER",
        16: "SYS_MODULE", 17: "SYS_RAWIO", 18: "SYS_CHROOT", 19: "SYS_PTRACE", 20: "SYS_PACCT",
        21: "SYS_ADMIN", 22: "SYS_BOOT", 23: "SYS_NICE", 24: "SYS_RESOURCE", 25: "SYS_TIME",
        26: "SYS_TTY_CONFIG", 27: "MKNOD", 28: "LEASE", 29: "AUDIT_WRITE", 30: "AUDIT_CONTROL",
        31: "SETFCAP", 32: "MAC_OVERRIDE", 33: "MAC_ADMIN", 34: "SYSLOG", 35: "WAKE_ALARM",
        36: "BLOCK_SUSPEND", 37: "AUDIT_READ", 38: "PERFMON", 39: "BPF", 40: "CHECKPOINT_RESTORE"}
DANGEROUS = {"SYS_ADMIN": CRITICAL, "SYS_MODULE": CRITICAL, "SYS_RAWIO": CRITICAL, "SYS_PTRACE": HIGH,
             "DAC_READ_SEARCH": HIGH, "NET_ADMIN": MEDIUM, "NET_RAW": MEDIUM, "MKNOD": MEDIUM,
             "SYS_TIME": MEDIUM, "SETFCAP": LOW, "AUDIT_CONTROL": LOW, "BPF": HIGH, "PERFMON": MEDIUM}


def caps_of(hexmask):
    mask = int(hexmask, 16)
    return {name for bit, name in CAPS.items() if mask & (1 << bit)}


def audit_container():
    c = "container"
    cgroup = read("/proc/1/cgroup") or ""
    in_ctr = os.path.exists("/.dockerenv") or "docker" in cgroup or "containerd" in cgroup \
        or (read("/proc/1/comm") or "").strip() in ("tini", "docker-init")
    A.expect(c, "Running inside a container", in_ctr, LOW,
             "container detected" if in_ctr else "no container markers", "run with docker",
             warn=True)

    pid1 = (read("/proc/1/comm") or "").strip()
    A.expect(c, "PID 1 is a minimal init (signals, zombies)", pid1 in ("tini", "docker-init"), LOW,
             pid1, "ENTRYPOINT [\"/usr/bin/tini\", \"--\", ...]")

    nnp = proc_status(1, "NoNewPrivs")
    A.expect(c, "no-new-privileges enforced", nnp == "1", HIGH, f"NoNewPrivs: {nnp}",
             "--security-opt no-new-privileges:true")
    sec = proc_status(1, "Seccomp")
    A.expect(c, "Seccomp filter active", sec == "2", HIGH, f"Seccomp: {sec}",
             "keep Docker's default seccomp profile (never seccomp=unconfined)")
    aa = (read("/proc/1/attr/current") or read("/proc/1/attr/apparmor/current") or "").strip().strip("\0")
    if aa:
        A.expect(c, "AppArmor/LSM profile applied", "unconfined" not in aa, MEDIUM, aa,
                 "keep docker-default AppArmor profile", warn=True)

    bnd = proc_status(1, "CapBnd")
    if bnd:
        held = caps_of(bnd)
        A.expect(c, "Not a privileged container", len(held) < 30, CRITICAL,
                 f"{len(held)} capabilities in bounding set", "never use --privileged")
        for cap, sev in sorted(DANGEROUS.items(), key=lambda x: SEV_ORDER[x[1]]):
            if cap in held:
                A.add(c, f"Capability {cap} dropped", FAIL, sev, "present in bounding set",
                      f"--cap-drop=ALL, add back only what is needed")
        if not held & set(DANGEROUS):
            A.add(c, "Dangerous capabilities dropped", PASS, HIGH,
                  f"bounding set: {', '.join(sorted(held)) or 'empty'}")

    sock = [p for p in ("/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock")
            if os.path.exists(p)]
    A.expect(c, "Docker socket not mounted", not sock, CRITICAL, ", ".join(sock) or "absent",
             "never mount /var/run/docker.sock (root on the host)")

    procsys = mounts().get("/proc/sys", [])
    A.expect(c, "/proc/sys read-only", "ro" in procsys, MEDIUM,
             ",".join(procsys[:2]) or "not a separate mount", "do not run privileged")

    mem = (read("/sys/fs/cgroup/memory.max") or read("/sys/fs/cgroup/memory/memory.limit_in_bytes") or "").strip()
    mem_ok = bool(mem) and mem != "max" and to_int(mem, 1 << 62) < 1 << 60
    A.expect(c, "Memory limit set", mem_ok, MEDIUM,
             f"{to_int(mem, 0) // 1048576} MiB" if mem_ok else (mem or "unknown"), "--memory=512m --memory-swap=512m")
    pids = (read("/sys/fs/cgroup/pids.max") or read("/sys/fs/cgroup/pids/pids.max") or "").strip()
    A.expect(c, "Process limit set (fork bombs)", bool(pids) and pids != "max", MEDIUM,
             pids or "unknown", "--pids-limit=200")
    cpu = (read("/sys/fs/cgroup/cpu.max") or "").strip()
    cpu_q = (read("/sys/fs/cgroup/cpu/cpu.cfs_quota_us") or "").strip()
    cpu_ok = (bool(cpu) and not cpu.startswith("max")) or (bool(cpu_q) and cpu_q != "-1")
    A.expect(c, "CPU limit set", cpu_ok, LOW, cpu or cpu_q or "unknown", "--cpus=1.0")

    env = read("/proc/1/environ")
    if env is None:
        A.add(c, "No secrets in environment variables", SKIP, HIGH, "needs root")
    else:
        names = [e.split("=", 1)[0] for e in env.split("\0") if "=" in e]
        leaked = [n for n in names if re.search(r"PASS|SECRET|TOKEN|PRIVATE|API_?KEY|CREDENTIAL", n, re.I)
                  and not n.endswith("_FILE")]
        A.expect(c, "No secrets in environment variables", not leaked, HIGH,
                 ", ".join(leaked) or f"{len(names)} variables, none sensitive",
                 "use Docker secrets (/run/secrets) instead of -e")
    secrets = glob.glob("/run/secrets/*")
    loose = [s for s in secrets if os.path.isfile(s) and (mode_of(s) or (0,))[0] & 0o004]
    if secrets:
        A.expect(c, "Mounted secrets not world-readable", not loose, MEDIUM,
                 ", ".join(loose) or f"{len(secrets)} secret(s)", "secrets: mode: 0400", warn=True)

    uid1 = [p for p in processes() if p[0] == 1]
    if uid1 and uid1[0][2] == 0:
        app = [p for p in processes() if p[1] == "nginx" and p[2] != 0]
        A.expect(c, "Application workload runs as a non-root user", bool(app), HIGH,
                 f"nginx as uid {app[0][2]}" if app else "no non-root app process",
                 f"run the application as {APP_USER}")


# =============================================================================
# Scoring and reports
# =============================================================================
def score(checks):
    possible = sum(WEIGHT[c.severity] for c in checks if c.status != SKIP)
    earned = sum(WEIGHT[c.severity] * CREDIT[c.status] for c in checks if c.status != SKIP)
    return round(100.0 * earned / possible, 1) if possible else 0.0


def summarize(threshold):
    cats = {}
    for key, (_, name) in CATEGORIES.items():
        cs = [c for c in A.checks if c.category == key]
        if not cs:
            continue
        crit = [c for c in cs if c.status == FAIL and c.severity == CRITICAL]
        sc = score(cs)
        cats[key] = {
            "name": name, "score": sc,
            "status": PASS if sc >= threshold and not crit else FAIL,
            "counts": {s: sum(c.status == s for c in cs) for s in (PASS, WARN, FAIL, SKIP)},
            "critical_failures": len(crit),
        }
    overall = score(A.checks)
    crit = [c for c in A.checks if c.status == FAIL and c.severity == CRITICAL]
    return {
        "score": overall,
        "status": PASS if overall >= threshold and not crit else FAIL,
        "threshold": threshold,
        "counts": {s: sum(c.status == s for c in A.checks) for s in (PASS, WARN, FAIL, SKIP)},
        "critical_failures": len(crit),
        "categories": cats,
    }


def context():
    osr = read("/etc/os-release") or ""
    m = re.search(r'^PRETTY_NAME="?([^"\n]*)', osr, re.M)
    return {
        "host": socket.gethostname(),
        "date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "os": m.group(1) if m else "unknown",
        "kernel": os.uname().release,
        "auditor": f"audit.py {VERSION}",
        "privileges": "root" if IS_ROOT else f"uid {os.geteuid()} (some checks skipped)",
    }


class Color:
    def __init__(self, on):
        self.on = on

    def __call__(self, text, code):
        return f"\033[{code}m{text}\033[0m" if self.on else text

    def status(self, s):
        return self(f"{s:<4}", {PASS: "32", WARN: "33", FAIL: "31;1", SKIP: "2"}[s])


def bar(pct, width=20):
    full = int(round(pct / 100 * width))
    return "#" * full + "." * (width - full)


def render_console(summary, ctx, color):
    out = []
    w = 78
    out += ["=" * w, color(" NovaTech Hardened Shield - Security Audit".ljust(w), "1"),
            f" {ctx['host']}  |  {ctx['date']}  |  {ctx['os']}  |  {ctx['privileges']}", "=" * w]
    for key, cat in summary["categories"].items():
        out += ["", color(f"[{cat['name']}]", "1;36") +
                f"  score {cat['score']:5.1f}%  {color.status(cat['status'])}"]
        for c in (c for c in A.checks if c.category == key):
            detail = f"  {color(c.detail, '2')}" if c.detail else ""
            out.append(f"  {color.status(c.status)} {c.id:<7} {c.title} ({c.severity}){detail}")
    out += ["", "=" * w, color(" SCORE PER CATEGORY", "1")]
    for cat in summary["categories"].values():
        out.append(f"  {cat['name']:<22} [{bar(cat['score'])}] {cat['score']:5.1f}%  {color.status(cat['status'])}")
    n = summary["counts"]
    out += ["-" * w,
            f"  {'OVERALL':<22} [{bar(summary['score'])}] {summary['score']:5.1f}%  {color.status(summary['status'])}",
            f"  {n[PASS]} passed, {n[WARN]} warnings, {n[FAIL]} failed, {n[SKIP]} skipped"
            f"  |  critical failures: {summary['critical_failures']}  |  threshold {summary['threshold']}%",
            "=" * w]
    return "\n".join(out) + "\n"


def md(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_markdown(summary, ctx):
    n = summary["counts"]
    verdict = "✅ PASS" if summary["status"] == PASS else "❌ FAIL"
    out = [
        "# Security Audit Report - NovaTech Hardened Shield", "",
        "| Field | Value |", "|---|---|",
        f"| Target | `{ctx['host']}` |",
        f"| Date | {ctx['date']} |",
        f"| Operating system | {ctx['os']} (kernel {ctx['kernel']}) |",
        f"| Tool | {ctx['auditor']} |",
        f"| Privileges | {ctx['privileges']} |",
        f"| Pass threshold | {summary['threshold']} % and no critical failure |",
    ] + ([f"| Environment | {md(ctx['note'])} |"] if ctx.get("note") else []) + [
        "",
        "## 1. Executive Summary", "",
        f"**Overall result: {verdict} - {summary['score']} %**", "",
        f"{len(A.checks)} controls audited: **{n[PASS]} passed**, {n[WARN]} warnings, "
        f"**{n[FAIL]} failed**, {n[SKIP]} skipped. Critical failures: **{summary['critical_failures']}**.", "",
        "| Category | Score | Status | Pass | Warn | Fail | Skip |", "|---|---:|:---:|---:|---:|---:|---:|",
    ]
    for cat in summary["categories"].values():
        k = cat["counts"]
        out.append(f"| {cat['name']} | {cat['score']} % | {cat['status']} | {k[PASS]} | {k[WARN]} | {k[FAIL]} | {k[SKIP]} |")
    out.append(f"| **Overall** | **{summary['score']} %** | **{summary['status']}** | {n[PASS]} | {n[WARN]} | {n[FAIL]} | {n[SKIP]} |")

    findings = sorted((c for c in A.checks if c.status in (FAIL, WARN)),
                      key=lambda c: (c.status != FAIL, SEV_ORDER[c.severity], c.id))
    out += ["", "## 2. Findings and Remediation", ""]
    if findings:
        out += ["| ID | Severity | Status | Finding | Observed | Remediation |", "|---|---|---|---|---|---|"]
        for c in findings:
            out.append(f"| {c.id} | {c.severity.upper()} | {c.status} | {md(c.title)} | {md(c.detail)} | {md(c.remediation)} |")
    else:
        out.append("No failed or warning controls.")

    out += ["", "## 3. Detailed Results", ""]
    for i, (key, cat) in enumerate(summary["categories"].items(), 1):
        out += [f"### 3.{i} {cat['name']} - {cat['score']} % ({cat['status']})", "",
                "| ID | Control | Severity | Status | Observed |", "|---|---|---|:---:|---|"]
        for c in (c for c in A.checks if c.category == key):
            out.append(f"| {c.id} | {md(c.title)} | {c.severity} | {c.status} | {md(c.detail)} |")
        out.append("")

    out += ["## 4. Methodology", "",
            "- Checks run inside the container and read live state: `/proc`, `/sys/fs/cgroup`, "
            "PAM and login files, the effective `sshd -T` configuration, and HTTP probes against Nginx.",
            "- Severity weights: critical 10, high 5, medium 3, low 1. PASS earns the full weight, "
            "WARN half, FAIL none; SKIP (not testable) is excluded.",
            "- Score = earned weight / possible weight. A category or the overall audit PASSES when "
            f"its score is at least {summary['threshold']} % and no CRITICAL control failed.",
            "- Host-level kernel settings (`kernel.*`, `fs.*`) are not namespaced: they reflect "
            "the Docker host and must be fixed there.", "",
            "*Report generated automatically by `audit.py`. Re-run after every image or "
            "configuration change.*", ""]
    return "\n".join(out)


# =============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="NovaTech Hardened Shield security audit",
        epilog="Exit codes: 0 overall PASS, 1 overall FAIL, 2 usage/output error.")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="write the Markdown report to FILE ('-' = stdout only)")
    parser.add_argument("--json", metavar="FILE", help="write JSON results to FILE ('-' = stdout)")
    parser.add_argument("--category", metavar="LIST",
                        help="comma-separated subset: " + ",".join(CATEGORIES))
    parser.add_argument("--threshold", type=float, default=80.0, help="pass threshold in %% (default 80)")
    parser.add_argument("--note", metavar="TEXT", help="environment note added to the report header")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    parser.add_argument("-q", "--quiet", action="store_true", help="no console report")
    parser.add_argument("--version", action="version", version=f"audit.py {VERSION}")
    args = parser.parse_args()

    selected = list(CATEGORIES)
    if args.category:
        selected = [s.strip() for s in args.category.split(",") if s.strip()]
        unknown = [s for s in selected if s not in CATEGORIES]
        if unknown:
            parser.error(f"unknown category: {', '.join(unknown)}")
    if not 0 < args.threshold <= 100:
        parser.error("--threshold must be in ]0, 100]")

    runners = {"kernel": audit_kernel, "filesystem": audit_filesystem, "identity": audit_identity,
               "service": audit_service, "container": audit_container}
    for key in selected:
        try:
            runners[key]()
        except Exception as exc:  # keep auditing the other categories
            A.add(key, "Category audit completed", FAIL, HIGH, f"audit error: {exc!r}",
                  "report this error; the category could not be fully audited")

    summary = summarize(args.threshold)
    ctx = context()
    if args.note:
        ctx["note"] = args.note
    stdout_used = args.output == "-" or args.json == "-"

    if not args.quiet and not stdout_used:
        color = Color(not args.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ)
        sys.stdout.write(render_console(summary, ctx, color))

    try:
        if args.output:
            report = render_markdown(summary, ctx)
            if args.output == "-":
                sys.stdout.write(report)
            else:
                with open(args.output, "w", encoding="utf-8") as fh:
                    fh.write(report)
                if not args.quiet:
                    print(f"Markdown report written to {args.output}")
        if args.json:
            data = json.dumps({"context": ctx, "summary": summary,
                               "checks": [asdict(c) for c in A.checks]}, indent=2)
            if args.json == "-":
                sys.stdout.write(data + "\n")
            else:
                with open(args.json, "w", encoding="utf-8") as fh:
                    fh.write(data + "\n")
    except OSError as exc:
        print(f"audit.py: cannot write report: {exc}", file=sys.stderr)
        return 2

    return 0 if summary["status"] == PASS else 1


if __name__ == "__main__":
    sys.exit(main())
