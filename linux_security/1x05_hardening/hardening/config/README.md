# config/

Ce dossier contient la configuration du framework.

## Fichier principal

- `harden.cfg`: toutes les variables de parametrage.

## Sections importantes

- `LOG_FILE` : chemin du log.
- `SSH_*` : port SSH, auth par mot de passe, auth par cle, root login.
- `ALLOW_HTTP` / `ALLOW_HTTPS` : ouverture de ports web dans la policy firewall.
- `PASS_*` / `FAIL_LOCK_ATTEMPTS` : regles mots de passe et verrouillage.
- `PACKAGES_REMOVE` / `PACKAGES_INSTALL` : paquets a retirer / installer.
- `ADMIN_GROUPS`, `MIN_UID_TO_CLEAN`, `PRESERVE_USERS` : regles de nettoyage des comptes.