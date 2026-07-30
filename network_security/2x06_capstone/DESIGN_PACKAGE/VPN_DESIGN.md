# Architecture VPN

## 1. Objectif

WireGuard devient le point d'entrée unique pour :

- l'administration distante ;
- l'accès distant des utilisateurs Finance au serveur FTP.

SSH et FTP ne sont plus exposés sur Internet.

## 2. Topologie

Architecture en étoile :

- Passerelle Linux = concentrateur WireGuard.
- Administrateurs.
- Utilisateurs Finance.
- Prestataires temporaires.

Les clients VPN ne communiquent jamais directement entre eux.

## 3. Plan d'adressage

| Équipement | Adresse VPN | Accès |
|---|---:|---|
| Passerelle | 10.200.0.1 | Routage VPN |
| Admin principal | 10.200.0.2 | Administration |
| Admin secondaire | 10.200.0.3 | Administration |
| Finance 1 | 10.200.0.10 | FTP uniquement |
| Finance 2 | 10.200.0.11 | FTP uniquement |

Chaque utilisateur possède une clé et une adresse dédiées.

## 4. Contrôle d'accès

Les autorisations sont appliquées :

1. par AllowedIPs de WireGuard ;
2. par nftables sur la passerelle.

Les utilisateurs Finance ne peuvent accéder qu'au serveur FTP.

## 5. Gestion des clés

- une paire de clés par utilisateur ;
- inventaire des clés ;
- révocation immédiate en cas de perte.

## 6. FTP Finance

Le protocole FTP est conservé.

Le tunnel WireGuard chiffre uniquement le transport Internet.

Le serveur FTP :

- reste dans la DMZ ;
- n'est jamais publié sur Internet ;
- est accessible uniquement par le VLAN Finance ou via WireGuard.

## 7. Acceptation du risque

Le maintien du FTP constitue une contrainte métier.

Le risque résiduel est accepté sous réserve :

- d'une DMZ ;
- du VPN ;
- du filtrage ;
- des comptes nominatifs ;
- d'une revue régulière des accès.
