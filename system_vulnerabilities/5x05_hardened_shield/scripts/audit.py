#!/usr/bin/env python3
"""audit.py - automated security audit of the Hardened Shield container.

Checks the controls of 5x02 (system hardening), 5x03 (identity) and
5x04 (container security) from inside the running container.

Usage:
    audit.py                      text report on stdout
    audit.py --format markdown    Markdown report (audit_result.md)
    audit.py --format json        machine-readable
    audit.py -o FILE              write the report to FILE

Exit code: 0 = no FAIL, 1 = at least one FAIL, 2 = usage error.
Run as root (docker exec) for full coverage: checks that need root are
reported as SKIP otherwise.
"""

import argparse
import datetime
import glob
import json
import os
import re
import socket
import stat
import subprocess
import sys
import urllib.request

PASS, FAIL, WARN, SKIP = "PASS", "FAIL", "WARN", "SKIP"
RESULTS = []


def record(category, name, status, detail=""):
    RESULTS.append({"category": category, "check": name,
                    "status": status, "detail": detail})


def read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except PermissionError:
        return None
    except OSError:
        return ""


def active_lines(text):
    return [l.strip() for l in (text or "").splitlines()
            if l.strip() and not l.strip().startswith("#")]


def conf_value(text, key, sep=r"\s*=\s*|\s+"):
    for line in active_lines(text):
        m = re.match(rf"{re.escape(key)}(?:{sep})(.*)$", line, re.I)
        if m:
            return m.group(1).strip()
    return None


def proc_status(pid, field):
    text = read(f"/proc/{pid}/status") or ""
    m = re.search(rf"^{field}:\s*(.*)$", text, re.M)
    return m.group(1).strip() if m else None


def processes():
    procs = []
    for d in glob.glob("/proc/[0-9]*"):
        comm = (read(f"{d}/comm") or "").strip()
        uid = proc_status(d.split("/")[-1], "Uid")
        if comm and uid:
            procs.append((comm, int(uid.split()[0])))
    return procs


# --------------------------------------------------------------------------
# 5x02 - system hardening
# --------------------------------------------------------------------------
def check_hardening():
    cat = "System hardening (5x02)"
    conf = read("/etc/sysctl.d/99-hardening.conf") or ""
    for line in active_lines(conf):
        key, _, want = (x.strip() for x in line.partition("="))
        have = (read("/proc/sys/" + key.replace(".", "/")) or "").strip()
        record(cat, f"sysctl {key} = {want}", PASS if have == want else FAIL,
               f"current: {have or 'n/a'}")

    mounts = read("/proc/mounts") or ""
    tmp = [l.split()[3] for l in mounts.splitlines() if l.split()[1:2] == ["/tmp"]]
    if not tmp:
        record(cat, "/tmp separate mount", FAIL, "not a separate mount")
    else:
        opts = tmp[-1].split(",")
        missing = [o for o in ("noexec", "nosuid", "nodev") if o not in opts]
        record(cat, "/tmp noexec,nosuid,nodev", FAIL if missing else PASS,
               "missing: " + ",".join(missing) if missing else tmp[-1])

    suid = []
    for root in ("/usr", "/bin", "/sbin", "/lib", "/opt", "/etc", "/var"):
        for dirpath, _, files in os.walk(root):
            for f in files:
                p = os.path.join(dirpath, f)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                if stat.S_ISREG(st.st_mode) and st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    suid.append(p)
    record(cat, "no SUID/SGID binaries", FAIL if suid else PASS,
           ", ".join(suid[:10]) if suid else "0 found")

    found = [t for t in ("gcc", "g++", "cc", "make", "as") if _which(t)]
    record(cat, "no compilers", FAIL if found else PASS, ", ".join(found) or "none")
    found = [t for t in ("nc", "netcat", "ncat", "nmap", "socat", "tcpdump", "telnet")
             if _which(t)]
    record(cat, "no network attack tools", FAIL if found else PASS, ", ".join(found) or "none")

    shadow = read("/etc/shadow")
    if shadow is None:
        record(cat, "root password locked", SKIP, "needs root")
    else:
        root = [l for l in shadow.splitlines() if l.startswith("root:")]
        locked = bool(root) and root[0].split(":")[1].startswith(("!", "*"))
        record(cat, "root password locked", PASS if locked else FAIL)

    st = os.stat("/etc/shadow")
    record(cat, "/etc/shadow mode 0640 or stricter",
           PASS if not st.st_mode & 0o037 else FAIL, oct(st.st_mode & 0o777))

    banner = read("/etc/issue.net") or ""
    record(cat, "legal banner", PASS if "AUTHORIZED" in banner.upper() else FAIL)

    limits = read("/etc/security/limits.d/99-hardening.conf") or ""
    record(cat, "core dumps disabled",
           PASS if re.search(r"\*\s+hard\s+core\s+0", limits) else FAIL)


def _which(cmd):
    for d in os.environ.get("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin").split(":"):
        if os.access(os.path.join(d, cmd), os.X_OK):
            return True
    return False


# --------------------------------------------------------------------------
# 5x03 - identity
# --------------------------------------------------------------------------
def check_identity():
    cat = "Identity (5x03)"
    pwq = read("/etc/security/pwquality.conf") or ""
    minlen = conf_value(pwq, "minlen")
    record(cat, "password minlen >= 12",
           PASS if minlen and int(minlen) >= 12 else FAIL, f"minlen={minlen}")
    for key in ("dcredit", "ucredit", "lcredit", "ocredit"):
        v = conf_value(pwq, key)
        record(cat, f"pwquality {key} <= -1",
               PASS if v and int(v) <= -1 else FAIL, f"{key}={v}")

    cpw = read("/etc/pam.d/common-password") or ""
    record(cat, "pam_pwquality active", PASS if "pam_pwquality.so" in cpw else FAIL)
    m = re.search(r"pam_pwhistory\.so.*remember=(\d+)", cpw)
    record(cat, "pam_pwhistory remember >= 5",
           PASS if m and int(m.group(1)) >= 5 else FAIL, m.group(0) if m else "absent")

    cauth = read("/etc/pam.d/common-auth") or ""
    ok = all(s in cauth for s in ("pam_faillock.so preauth", "pam_faillock.so authfail"))
    record(cat, "pam_faillock active", PASS if ok else FAIL)
    fl = read("/etc/security/faillock.conf") or ""
    deny, unlock = conf_value(fl, "deny"), conf_value(fl, "unlock_time")
    record(cat, "faillock deny <= 5", PASS if deny and int(deny) <= 5 else FAIL, f"deny={deny}")
    record(cat, "faillock unlock_time >= 900",
           PASS if unlock and (unlock == "never" or int(unlock) >= 900) else FAIL,
           f"unlock_time={unlock}")

    defs = read("/etc/login.defs") or ""
    mx = conf_value(defs, "PASS_MAX_DAYS", r"\s+")
    record(cat, "PASS_MAX_DAYS <= 90", PASS if mx and int(mx) <= 90 else FAIL, f"{mx}")
    mn = conf_value(defs, "PASS_MIN_DAYS", r"\s+")
    record(cat, "PASS_MIN_DAYS >= 1", PASS if mn and int(mn) >= 1 else FAIL, f"{mn}")

    passwd = read("/etc/passwd") or ""
    uid0 = [l.split(":")[0] for l in passwd.splitlines() if l.split(":")[2:3] == ["0"]]
    record(cat, "only root has UID 0", PASS if uid0 == ["root"] else FAIL, ", ".join(uid0))
    app = [l for l in passwd.splitlines() if l.startswith("appuser:")]
    record(cat, "appuser exists with nologin shell",
           PASS if app and app[0].endswith("nologin") else FAIL)

    shadow = read("/etc/shadow")
    if shadow is None:
        record(cat, "no empty passwords", SKIP, "needs root")
    else:
        empty = [l.split(":")[0] for l in shadow.splitlines() if l.split(":")[1:2] == [""]]
        record(cat, "no empty passwords", FAIL if empty else PASS, ", ".join(empty))

    sshd = read("/etc/ssh/sshd_config")
    if sshd is None:
        record(cat, "sshd configuration", SKIP, "needs root")
        return
    expected = {
        "PermitRootLogin": "no",
        "PasswordAuthentication": "no",
        "PermitEmptyPasswords": "no",
        "PubkeyAuthentication": "yes",
        "X11Forwarding": "no",
        "AllowTcpForwarding": "no",
        "PermitUserEnvironment": "no",
        "UsePAM": "yes",
    }
    for key, want in expected.items():
        have = conf_value(sshd, key, r"\s+")
        record(cat, f"sshd {key} {want}",
               PASS if (have or "").lower() == want else FAIL, f"current: {have}")
    tries = conf_value(sshd, "MaxAuthTries", r"\s+")
    record(cat, "sshd MaxAuthTries <= 3",
           PASS if tries and int(tries) <= 3 else FAIL, f"current: {tries}")
    record(cat, "sshd AllowGroups set",
           PASS if conf_value(sshd, "AllowGroups", r"\s+") else FAIL)
    record(cat, "sshd Banner set", PASS if conf_value(sshd, "Banner", r"\s+") else FAIL)
    baked = glob.glob("/etc/ssh/ssh_host_*_key")
    record(cat, "no SSH host key baked in image", FAIL if baked else PASS,
           ", ".join(baked) or "keys generated at runtime")


# --------------------------------------------------------------------------
# 5x04 - container security
# --------------------------------------------------------------------------
def check_container():
    cat = "Container security (5x04)"
    procs = processes()
    nginx = [uid for comm, uid in procs if comm == "nginx"]
    if not nginx:
        record(cat, "nginx running", FAIL, "no nginx process")
    else:
        record(cat, "nginx runs as non-root (master + workers)",
               PASS if all(u != 0 for u in nginx) else FAIL,
               f"uids: {sorted(set(nginx))}")
    record(cat, "sshd running", PASS if any(c == "sshd" for c, _ in procs) else FAIL)

    pid1 = (read("/proc/1/comm") or "").strip()
    record(cat, "PID 1 is an init (tini)", PASS if pid1 in ("tini", "docker-init") else WARN, pid1)

    nnp = proc_status(1, "NoNewPrivs")
    record(cat, "no-new-privileges", PASS if nnp == "1" else FAIL, f"NoNewPrivs={nnp}")
    seccomp = proc_status(1, "Seccomp")
    record(cat, "seccomp filter active", PASS if seccomp == "2" else FAIL, f"Seccomp={seccomp}")

    capbnd = proc_status(1, "CapBnd")
    if capbnd:
        caps = int(capbnd, 16)
        dangerous = {"CAP_SYS_ADMIN": 21, "CAP_NET_RAW": 13, "CAP_SYS_PTRACE": 19,
                     "CAP_SYS_MODULE": 16, "CAP_DAC_READ_SEARCH": 2, "CAP_MKNOD": 27}
        held = [n for n, b in dangerous.items() if caps & (1 << b)]
        record(cat, "capabilities dropped (no SYS_ADMIN, NET_RAW, ...)",
               FAIL if "CAP_SYS_ADMIN" in held else (WARN if held else PASS),
               f"CapBnd={capbnd} " + (("held: " + ",".join(held)) if held else ""))

    mounts = read("/proc/mounts") or ""
    root = [l.split()[3] for l in mounts.splitlines() if l.split()[1:2] == ["/"]]
    ro = bool(root) and "ro" in root[-1].split(",")
    record(cat, "read-only root filesystem", PASS if ro else WARN,
           root[-1] if root else "unknown")

    cg = (read("/sys/fs/cgroup/memory.max") or read("/sys/fs/cgroup/memory/memory.limit_in_bytes") or "").strip()
    limited = cg and cg != "max" and int(cg) < 1 << 60
    record(cat, "memory limit set", PASS if limited else WARN, cg or "unknown")
    pids = (read("/sys/fs/cgroup/pids.max") or read("/sys/fs/cgroup/pids/pids.max") or "").strip()
    record(cat, "pids limit set", PASS if pids and pids != "max" else WARN, pids or "unknown")

    env = read("/proc/1/environ")
    if env is None:
        record(cat, "no secrets in environment", SKIP, "needs root")
    else:
        names = [kv.split("=", 1)[0] for kv in env.split("\0") if "=" in kv]
        bad = [n for n in names if re.search(r"PASS|SECRET|TOKEN|PRIVATE|API_?KEY", n, re.I)]
        record(cat, "no secrets in environment", FAIL if bad else PASS, ", ".join(bad))

    try:
        with urllib.request.urlopen("http://127.0.0.1:8080/health", timeout=3) as r:
            body, headers = r.read().decode(), r.headers
        record(cat, "HEALTHCHECK endpoint /health", PASS if "OK" in body else FAIL)
        server = headers.get("Server", "")
        record(cat, "server_tokens off", PASS if not re.search(r"\d", server) else FAIL, server)
        missing = [h for h in ("X-Frame-Options", "X-Content-Type-Options",
                               "Content-Security-Policy", "Referrer-Policy")
                   if h not in headers]
        record(cat, "security headers", FAIL if missing else PASS,
               "missing: " + ", ".join(missing) if missing else "all present")
    except Exception as exc:  # noqa: BLE001 - any failure = web down
        record(cat, "HEALTHCHECK endpoint /health", FAIL, str(exc))

    for port, name in ((8080, "web"), (22, "ssh")):
        s = socket.socket()
        s.settimeout(2)
        up = s.connect_ex(("127.0.0.1", port)) == 0
        s.close()
        record(cat, f"{name} listening on :{port}", PASS if up else FAIL)


# --------------------------------------------------------------------------
def render(fmt):
    counts = {k: sum(r["status"] == k for r in RESULTS) for k in (PASS, FAIL, WARN, SKIP)}
    scored = counts[PASS] + counts[FAIL]
    score = round(100 * counts[PASS] / scored, 1) if scored else 0.0
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    host = socket.gethostname()

    if fmt == "json":
        return json.dumps({"host": host, "date": now, "score": score,
                           "summary": counts, "results": RESULTS}, indent=2)

    cats = list(dict.fromkeys(r["category"] for r in RESULTS))
    out = []
    if fmt == "markdown":
        out += ["# Hardened Shield - Security Audit Result", "",
                f"- **Host:** `{host}`", f"- **Date:** {now}",
                f"- **Score:** {score}% ({counts[PASS]} PASS / {counts[FAIL]} FAIL, "
                f"{counts[WARN]} WARN, {counts[SKIP]} SKIP)", ""]
        for c in cats:
            out += [f"## {c}", "", "| Status | Check | Detail |", "|---|---|---|"]
            for r in (r for r in RESULTS if r["category"] == c):
                detail = r["detail"].replace("|", "\\|")
                out.append(f"| {r['status']} | {r['check']} | {detail} |")
            out.append("")
    else:
        out += ["=" * 70, " Hardened Shield - Security Audit", f" {host}  {now}", "=" * 70]
        for c in cats:
            out += ["", f"--- {c} ---"]
            for r in (r for r in RESULTS if r["category"] == c):
                line = f"  [{r['status']}] {r['check']}"
                out.append(line + (f"  ({r['detail']})" if r["detail"] else ""))
        out += ["", "=" * 70,
                f" PASS {counts[PASS]}  FAIL {counts[FAIL]}  WARN {counts[WARN]}  "
                f"SKIP {counts[SKIP]}   SCORE {score}%", "=" * 70]
    return "\n".join(out) + "\n"


def main():
    parser = argparse.ArgumentParser(description="Hardened Shield security audit")
    parser.add_argument("--format", choices=("text", "markdown", "json"), default="text")
    parser.add_argument("-o", "--output", help="write report to this file")
    args = parser.parse_args()

    for check in (check_hardening, check_identity, check_container):
        try:
            check()
        except Exception as exc:  # noqa: BLE001 - keep auditing other domains
            record(check.__name__, "check crashed", FAIL, repr(exc))

    report = render(args.format)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"report written to {args.output}")
    else:
        sys.stdout.write(report)
    return 1 if any(r["status"] == FAIL for r in RESULTS) else 0


if __name__ == "__main__":
    sys.exit(main())
