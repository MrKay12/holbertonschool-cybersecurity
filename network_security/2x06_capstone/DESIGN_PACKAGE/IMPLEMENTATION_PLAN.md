# Plan d'implémentation

## Principes

Chaque modification doit pouvoir être annulée rapidement.

Conditions :

- sauvegarde ;
- accès console ;
- rollback testé ;
- validation fonctionnelle.

Le FTP Finance reste opérationnel pendant toute la migration.

## Phase 0

Préparation :

- sauvegarde ;
- inventaire ;
- conservation des preuves.

## Phase 1

Réduction des risques :

- rotation des mots de passe ;
- comptes administrateurs nominatifs ;
- désactivation de l'accès FTP anonyme ;
- suppression des services inutiles.

## Phase 2

Déploiement de WireGuard en parallèle de l'infrastructure actuelle.

Validation :

- VPN fonctionnel ;
- SSH via VPN ;
- FTP Finance via VPN.

## Phase 3

Déploiement progressif des règles nftables.

Un rollback automatique est prévu avant chaque activation.

## Phase 4

Suppression des accès WAN :

- SSH ;
- FTP ;
- ttyd ;
- OpenVSCode.

Seul UDP 51820 reste accessible.

## Phase 5

Migration des VLAN :

1. Invités
2. Administration
3. DMZ
4. Serveurs
5. Finance
6. LAN

## Phase 6

Migration du serveur FTP dans la DMZ.

Le protocole FTP reste inchangé.

## Phase 7

Migration de la base de données.

Accès uniquement depuis les serveurs applicatifs.

## Phase 8

Durcissement :

- Fail2Ban ;
- Suricata ;
- journalisation centralisée ;
- contrôle d'intégrité.

## Validation finale

Les tests doivent confirmer :

- VPN opérationnel ;
- FTP Finance fonctionnel ;
- SSH uniquement via VPN ;
- segmentation effective ;
- accès invités isolés.

La documentation finale doit inclure le plan d'adressage, les règles nftables, l'inventaire WireGuard et les procédures de retour arrière.
