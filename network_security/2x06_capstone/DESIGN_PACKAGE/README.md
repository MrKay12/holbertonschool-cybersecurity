# DESIGN_PACKAGE

Ce dossier contient le design cible de l'architecture Zero Trust de la passerelle LogiCorp.

## Contenu

- **DESIGN_TOPOLOGY.png** : schéma de l'architecture cible et des flux autorisés.
- **TOPOLOGY.png** : copie de compatibilité du schéma.
- **FIREWALL_POLICY.md** : politique de filtrage nftables et justification des règles.
- **VPN_DESIGN.md** : architecture WireGuard, plan d'adressage et contrôle d'accès.
- **IMPLEMENTATION_PLAN.md** : plan de déploiement progressif et procédures de retour arrière.

## Contrainte métier

Le service **FTP utilisé par la Finance est conservé**. Il n'est jamais exposé directement sur Internet. Les utilisateurs Finance locaux accèdent au serveur FTP via le VLAN Finance et les utilisateurs distants utilisent un tunnel WireGuard.
