# lib/

Modules Bash utilises par `harden.sh`.

## Fichiers

- `system.sh`
	- fonctions communes: log, backup, ecriture de directives, audit report
	- hardening systeme: `apt update/upgrade`, suppression/install de paquets
- `network.sh`
	- genere une policy firewall simple dans `FIREWALL_POLICY_FILE`
	- applique des reglages kernel dans `sysctl.conf`
- `ssh.sh`
	- durcit `sshd_config` (port, auth password/pubkey, root login)
	- valide la config avec `sshd -t` si disponible
- `identity.sh`
	- politique mot de passe (`login.defs`, PAM)
	- verrouillage apres echecs (`pam_faillock`)
	- nettoyage de comptes non autorises selon config
	- verrouille le mot de passe root

## Notes

- Les modules utilisent les variables chargees depuis `config/harden.cfg`.
- Le script est idempotent sur plusieurs points (remplacement de directives, lignes uniques, backup unique).
