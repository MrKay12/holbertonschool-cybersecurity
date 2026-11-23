# 5x03 — Identity Fortress

Identity and Access Management hardening for the NovaTech bastion
(`novatech-prod-03`). This builds on the 5x02 system hardening: after a red
team cracked three SSH accounts with Hydra, the authentication stack (PAM, SSH,
account lifecycle) gets overhauled.

## Objectives

- **Enforce quality:** password complexity with `pam_pwquality`
- **Remember history:** block password reuse with `pam_pwhistory`
- **Punish guessing:** account lockout with `pam_faillock` and IP bans with fail2ban
- **Kill the password:** key-only SSH authentication
- **Add a second factor:** TOTP with Google Authenticator for critical access
- **Manage lifecycle:** password aging and account expiration with `chage`

## Tasks

| File | Description |
|------|-------------|
| `1-pam_audit.sh` | Read-only audit of the current PAM, password aging and SSH authentication settings, ending with an overall rating (WEAK / MODERATE / STRONG). It first warns if apt/dpkg is running (dpkg can rewrite PAM files mid-audit). `sudo ./1-pam_audit.sh --clear-stale-locks` also removes leftover apt/dpkg lock files when no package manager is running, then verifies the cleanup |
| `2-password_complexity.sh` | Installs `libpam-pwquality` (waiting for a running apt/dpkg, then clearing and verifying stale locks), backs up `pwquality.conf` and `common-password`, enforces minlen 12, upper/lower/digit/special, no username and difok 3, adds `pam_pwquality.so` to the PAM password stack, and tests that `weak` and `Password123` are rejected (via `pwscore`) |
| `3-test_complexity.sh` | Tests the policy with five passwords (dictionary word, no special character, too short, contains the username, strong) by running the real `passwd` as a throwaway user `audit` (removed on exit), so the full PAM password stack is exercised without touching a real account. Fails if any weak password is accepted or the strong one rejected. `-v` shows the PAM message |
| `4-password_history.sh` | Creates `/etc/security/opasswd` (root-only), adds `pam_pwhistory.so remember=5` before `pam_unix` in `common-password` (backup in `common-password.bak`), reports the hash algorithm, and tests with a throwaway user that switching back to the previous password is blocked |
| `5-password_aging.sh` | Backs up `/etc/login.defs` (`.bak`), sets `PASS_MAX_DAYS 90`, `PASS_MIN_DAYS 1`, `PASS_WARN_AGE 14` for new accounts, then applies them with `chage` to existing human accounts (UID in `UID_MIN`–`UID_MAX`, real login shell) and reads the values back from `/etc/shadow`. Service accounts are skipped |
| `6-force_password_change.sh` | `sudo ./6-force_password_change.sh user1 [user2 ...]` expires each user's password (`passwd -e`, fallback `chage -d 0`) so it must be changed at next login, and confirms each user with `chage -l` ("password must be changed"). Unknown users are reported and make the script exit 1 |
| `8-configure_faillock.sh` | Adds `pam_faillock` (preauth first, authfail just before `pam_deny`, renumbering the `[success=N]` jumps so the stack logic is preserved) to `common-auth` and `common-account`, writes `deny = 5`, `unlock_time = 900`, `fail_interval = 900` to `faillock.conf`, then tests with a throwaway user: correct password works, 5 wrong ones, correct password refused. All files backed up to `.bak` and restored automatically if auth breaks. root is not locked (emergency access) |
| `9-faillock_manage.sh` | `status` lists locked accounts with failure count and unlock time; `show <user>` lists each failure (time, source) and the lock state; `reset <user>` runs `faillock --user <user> --reset` and verifies no failure is left. Lock state follows `deny` / `fail_interval` / `unlock_time` from `faillock.conf` |
| `10-configure_fail2ban.sh` | Installs fail2ban (same apt lock/repair handling as task 2), writes `/etc/fail2ban/jail.local` with an `[sshd]` jail (`maxretry = 5`, `findtime = 600`, `bantime = 3600`), validates it with `fail2ban-client -t`, starts the service and shows the jail status. Uses `/var/log/auth.log`, or `backend = systemd` when that file does not exist. Localhost and the admin's SSH client IP are in `ignoreip` |
| `11-fail2ban_manage.sh` | `status` shows the service, jail list and `sshd` banned/total/failed counts; `banned` lists the `sshd` jail's banned IPs with ban and expiry times (`get sshd banip --with-time`, plain list on older fail2ban); `unban <ip>` validates the IP, runs `fail2ban-client set sshd unbanip` and verifies it is gone |
| `12-generate_ssh_key.sh` | Run as the key owner (no sudo). Generates `~/.ssh/id_ed25519` with `ssh-keygen -t ed25519 -a 100` (passphrase prompted), sets `~/.ssh` 700, private key 600, public key 644, and prints the fingerprint and public key. Never overwrites an existing key |
| `13-deploy_ssh_key.sh` | `./13-deploy_ssh_key.sh "<public key>"` validates the key with `ssh-keygen -lf`, creates `~/.ssh` (700), appends the key to `authorized_keys` (600) unless the same key is already there, then verifies key count, permissions and ownership |
| `14-disable_password_auth.sh` | Refuses to run unless the sudo user has a valid key in `authorized_keys`, tries a real key-only login to localhost (asks for `YES` if it cannot be tested; `--force` skips that), backs up `sshd_config` to `.backup.<date>`, sets `PasswordAuthentication no`, `KbdInteractiveAuthentication`/`ChallengeResponseAuthentication no`, `PubkeyAuthentication yes` in `sshd_config` and in `sshd_config.d/00-identity-fortress.conf` (overrides cloud-init's drop-in), keeps `UsePAM yes`, validates with `sshd -t` (rollback on failure), reloads SSH and checks the effective values with `sshd -T` |

## Emergency recovery

- **Locked user:** `sudo ./9-faillock_manage.sh reset <name>` (or `sudo faillock --user <name> --reset`)
- **Banned IP:** `sudo ./11-fail2ban_manage.sh unban <ip>` (or `sudo fail2ban-client set sshd unbanip <ip>`)
- **Broken PAM stack:** keep a root shell open while testing; restore with
  `cp /etc/pam.d/common-auth.bak /etc/pam.d/common-auth` (same for
  `common-account`, `common-password`, `/etc/security/faillock.conf`).
- **Locked out of SSH (task 14):** from the VM console or `multipass shell`,
  `cp /etc/ssh/sshd_config.backup.<date> /etc/ssh/sshd_config`,
  `rm /etc/ssh/sshd_config.d/00-identity-fortress.conf`, `systemctl reload ssh`.
- **No shell left:** Multipass VM: `multipass shell novatech-prod-03`, or
  boot to recovery mode and restore the `.bak` files.

## Safety rules

- Always back up `/etc/pam.d/` files before modifying them.
- Keep a root session open and test changes from a second terminal.
- Never test account lockout on your only access method.
- Document emergency recovery procedures.

## Environment

Tested on Kali Linux, ParrotOS and Ubuntu. All scripts start with
`#!/bin/bash` and must be executable.
