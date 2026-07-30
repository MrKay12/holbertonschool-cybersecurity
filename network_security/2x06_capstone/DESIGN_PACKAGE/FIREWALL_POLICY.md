# Politique de Pare-feu

## 1. Objectif

Cette politique met en œuvre un modèle **Zero Trust** avec une stratégie **Tout est refusé par défaut** sur la passerelle Linux, tout en conservant les services métiers indispensables (SSH d'administration, base de données et FTP Finance).

La passerelle est le seul équipement autorisé à router les communications entre les différentes zones de sécurité.

## 2. Zones de sécurité

| Zone | Interface | Adressage | Rôle |
|---|---|---|---|
| WAN | eth0 | Fourni par le FAI | Internet |
| LAN | vlan10 | 10.10.10.0/24 | Utilisateurs |
| Finance | vlan20 | 10.10.20.0/24 | Utilisateurs Finance |
| DMZ | vlan30 | 10.10.30.0/24 | Serveur FTP et services exposés |
| Serveurs | vlan40 | 10.10.40.0/24 | Base de données |
| Invités | vlan50 | 10.10.50.0/24 | Internet uniquement |
| Administration | vlan60 | 10.10.60.0/24 | Administration |
| VPN | wg0 | 10.200.0.0/24 | Accès distants |

## 3. Politique par défaut

- INPUT : DROP
- FORWARD : DROP
- OUTPUT : ACCEPT

Justification :
- protection de la passerelle ;
- blocage des mouvements latéraux ;
- limitation de l'impact sur la production.

## 4. Ordre des règles

1. Paquets invalides.
2. Trafic établi.
3. Loopback.
4. Services d'infrastructure.
5. VPN WireGuard.
6. Administration.
7. Flux métiers.
8. NAT Internet.
9. Journalisation.
10. Refus final.

## 5. Règles principales

- SSH uniquement depuis le réseau Administration et le VPN.
- FTP autorisé uniquement :
  - depuis le VLAN Finance ;
  - depuis les utilisateurs Finance connectés au VPN.
- Base de données accessible uniquement par les serveurs applicatifs.
- Réseau Invités isolé.
- Tout flux non documenté est refusé.

## 6. Politique FTP

Le protocole FTP est conservé pour répondre aux contraintes métier.

Mesures compensatoires :

- aucun accès WAN ;
- DMZ dédiée ;
- VPN obligatoire pour les accès distants ;
- plage passive fixe ;
- comptes nominatifs ;
- accès anonyme interdit ;
- journalisation complète.

## 7. NAT

Seul le trafic vers Internet est soumis au masquerading. Les communications internes ne sont jamais NATées afin de conserver la traçabilité.

## 8. Journalisation

Les refus sont enregistrés avec limitation de débit afin d'éviter l'inondation des journaux.

Les exemples de configuration nftables du document d'origine sont conservés sans modification.
