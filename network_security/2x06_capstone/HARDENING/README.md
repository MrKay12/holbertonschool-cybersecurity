# HARDENING

Scripts idempotents de transformation de la passerelle LogiCorp en bastion securise.

## Principe de configuration

Toutes les interfaces, adresses IP, plages reseau, ports, pairs WireGuard et flux Internet sont definis dans `hardening.conf`.

Les scripts ne contiennent aucune adresse IP metier en dur.

## Fichiers

- `hardening.conf` : source unique de configuration.
- `clean.sh` : durcissement systeme, SSH, Fail2Ban et sysctl.
- `vpn_setup.sh` : creation idempotente de WireGuard et des clients.
- `firewall.sh` : generation automatique du ruleset nftables.
- `panic.sh` : rollback automatique du pare-feu.
- `install.sh` : installation locale.

## Idempotence

- les paquets ne sont installes que s'ils sont absents ;
- les groupes et appartenances peuvent deja exister ;
- les cles WireGuard existantes sont reutilisees ;
- les configurations clientes sont regenerees avec les memes cles ;
- le ruleset nftables est entierement regenere depuis `hardening.conf` ;
- le ruleset est valide avec `nft -c` avant chargement ;
- le rollback est arme avant chaque modification du pare-feu ;
- `clean.sh` refuse de desactiver les mots de passe SSH sans utilisateur et cle valides.

## Utilisation

```bash
sudo ./install.sh
sudo nano /etc/logicorp/hardening.conf
sudo logicorp-clean
sudo logicorp-vpn-setup
sudo logicorp-firewall
```

Apres verification de SSH, WireGuard, FTP et de la base :

```bash
sudo /usr/local/sbin/panic.sh --confirm
```
