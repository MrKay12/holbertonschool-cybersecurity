# hardening/

Framework Bash de hardening compose d'un script principal, d'un fichier de config, et de modules.

## Execution

```bash
cd hardening
sudo ./harden.sh
```

## Sequence d'execution

`harden.sh` execute les etapes suivantes:

1. Charge la config et les librairies.
2. Prepare le log et le rapport d'audit.
3. Verifie l'execution en root.
4. Lance, dans l'ordre:
	- hardening systeme
	- hardening reseau
	- hardening SSH
	- hardening identite
5. Finalise le rapport et affiche un resume.

## Resultats

- Log detaille: `/var/log/hardening.log`
- Rapport final: `audit_report.txt` (dans ce dossier)