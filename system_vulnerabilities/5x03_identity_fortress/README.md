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
| `6-force_password_change.sh` | `sudo ./6-force_password_change.sh user1 [user2 ...]` expires each user's password (`passwd -e`, fallback `chage -d 0`) so it must be changed at next login, confirms it in `/etc/shadow`, and shows `chage -l` as proof. Unknown users are reported and make the script exit 1 |

## Safety rules

- Always back up `/etc/pam.d/` files before modifying them.
- Keep a root session open and test changes from a second terminal.
- Never test account lockout on your only access method.
- Document emergency recovery procedures.

## Environment

Tested on Kali Linux, ParrotOS and Ubuntu. All scripts start with
`#!/bin/bash` and must be executable.
