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
| `1-pam_audit.sh` | Read-only audit of the current PAM, password aging and SSH authentication settings, ending with an overall rating (WEAK / MODERATE / STRONG) |

## Safety rules

- Always back up `/etc/pam.d/` files before modifying them.
- Keep a root session open and test changes from a second terminal.
- Never test account lockout on your only access method.
- Document emergency recovery procedures.

## Environment

Tested on Kali Linux, ParrotOS and Ubuntu. All scripts start with
`#!/bin/bash` and must be executable.
