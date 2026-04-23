# 1x05_hardening

Ce dossier contient un mini framework Bash pour appliquer un hardening de base sur une machine Linux (Debian/Ubuntu).

## Objectif

- Appliquer des regles systeme, reseau, SSH et identite.
- Garder des traces dans un log.
- Produire un rapport d'audit simple en fin d'execution.

## Structure

- `hardening/harden.sh` : point d'entree principal.
- `hardening/config/harden.cfg` : configuration centralisee.
- `hardening/lib/` : modules de hardening (`system`, `network`, `ssh`, `identity`).
- `audit_report.txt` : exemple de rapport genere.

## Utilisation rapide

```bash
cd hardening
sudo ./harden.sh
```

## Fichiers produits

- Log runtime: `/var/log/hardening.log`
- Rapport audit: `hardening/audit_report.txt`
- Backups automatiques: `*.bak` sur certains fichiers modifies (ex: `sshd_config.bak`)

## Important

- Ce script modifie des fichiers sensibles (`/etc/ssh/sshd_config`, `/etc/sysctl.conf`, PAM, etc.).
- Tester d'abord sur VM/lab.
- Relire `hardening/config/harden.cfg` avant execution en production.
