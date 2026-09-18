# Nexus Financial - Politique de Contrôle d'Accès

## 1. Objectif

Cette politique définit les règles d'accès aux systèmes de Nexus Financial.

Elle repose sur trois principes :

* **Authentification forte**
* **Moindre privilège**
* **Accès réseau limité**

L'objectif est de maintenir l'efficacité des équipes tout en supprimant les pratiques dangereuses comme la clé SSH partagée `nexus_master.pem`.

---

# 2. Authentification

## 2.1 Comptes individuels

Chaque utilisateur doit disposer d'un compte personnel.

Les comptes partagés sont interdits pour les accès administratifs.

Chaque action privilégiée doit pouvoir être associée à un utilisateur précis.

## 2.2 Accès SSH

La clé partagée :

`nexus_master.pem`

doit être **révoquée et supprimée**.

Chaque administrateur ou développeur autorisé doit posséder sa propre paire de clés SSH.

Exemple :

```bash
ssh-keygen -t ed25519
```

La clé privée reste sur le poste de l'utilisateur.

Seule la clé publique est installée sur les serveurs autorisés dans :

```text
~/.ssh/authorized_keys
```

Les clés privées ne doivent jamais être :

* envoyées dans Slack ;
* partagées entre utilisateurs ;
* stockées dans Git ;
* écrites dans des scripts.

## 2.3 Authentification SSH

L'authentification SSH par mot de passe doit être désactivée :

```text
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
```

Les connexions directes avec le compte `root` sont interdites.

## 2.4 MFA

L'authentification multifacteur doit être activée pour les services critiques lorsque cela est techniquement possible, notamment :

* services Cloud ;
* comptes administrateurs ;
* VPN ;
* gestion des dépôts de code ;
* outils contenant des secrets.

## 2.5 Mots de passe

Les mots de passe et PIN faibles ou prévisibles sont interdits.

Le PIN `1975` du compte administrateur doit être remplacé.

Les secrets ne doivent jamais être affichés sur un tableau blanc, stockés en clair ou envoyés dans une messagerie.

---

# 3. Autorisation

## 3.1 Principe du moindre privilège

Un utilisateur ne doit disposer que des permissions nécessaires à son travail.

L'accès `root` généralisé aux développeurs doit être supprimé.

Les privilèges doivent être attribués selon le rôle de l'utilisateur.

## 3.2 RBAC

Les utilisateurs Linux doivent être organisés en groupes.

Exemple :

```text
developers
operations
security
```

### Developers

Les développeurs peuvent :

* consulter les applications nécessaires ;
* déployer dans les environnements autorisés ;
* consulter les logs applicatifs nécessaires.

Ils ne disposent pas d'un accès `root` complet.

### Operations

L'équipe Operations peut :

* gérer les services ;
* effectuer les opérations de maintenance ;
* réaliser les déploiements autorisés ;
* intervenir sur les serveurs de production.

### Security

L'équipe Security peut :

* consulter les logs de sécurité ;
* effectuer les audits ;
* analyser les incidents ;
* gérer certaines configurations de sécurité.

## 3.3 Sudo

Les droits administratifs doivent être accordés avec `sudo`.

Les permissions doivent être définies dans :

```text
/etc/sudoers.d/
```

Il est interdit d'utiliser :

```text
ALL=(ALL) ALL
```

pour tous les développeurs.

Les commandes autorisées doivent être définies selon le rôle.

Exemple :

```text
%operations ALL=(root) /usr/bin/systemctl restart nexus-app
```

Ainsi, un utilisateur peut redémarrer l'application sans obtenir un accès `root` complet.

## 3.4 Permissions des fichiers

Les fichiers sensibles doivent appartenir au bon utilisateur et au bon groupe.

Les permissions globales en écriture comme :

```text
chmod 777
```

sont interdites.

Les permissions doivent suivre le principe :

```text
Owner -> nécessaire
Group -> nécessaire
Others -> minimum
```

## 3.5 Départ d'un employé

Lorsqu'un employé quitte Nexus Financial :

* son compte doit être désactivé ;
* ses clés SSH doivent être supprimées ;
* ses accès VPN doivent être révoqués ;
* ses sessions actives doivent être invalidées ;
* ses accès Cloud et applications doivent être supprimés.

Cela évite une situation comme celle de Kevin, parti depuis plusieurs mois mais dont les automatisations et accès n'ont pas été vérifiés.

---

# 4. Réseau

## 4.1 Principe général

Aucun service interne sensible ne doit être directement exposé à Internet sans justification.

La règle par défaut doit être :

```text
DENY
```

Seuls les flux explicitement nécessaires doivent être autorisés.

## 4.2 PostgreSQL

La règle actuelle exposant PostgreSQL à :

```text
0.0.0.0/0:5432
```

doit être supprimée.

Le port :

```text
5432/tcp
```

doit uniquement être accessible depuis les serveurs applicatifs autorisés ou depuis le réseau VPN d'administration.

## 4.3 SSH

Le port :

```text
22/tcp
```

ne doit pas être accessible publiquement depuis n'importe quelle adresse Internet.

L'administration doit passer par :

```text
Utilisateur
    |
    v
VPN
    |
    v
Réseau d'administration
    |
    v
SSH
    |
    v
Serveur
```

## 4.4 VPN

Les employés distants doivent utiliser un VPN pour accéder aux ressources internes.

L'équipe distante de Bali doit donc utiliser :

```text
Internet -> VPN -> Ressource autorisée
```

et non :

```text
Internet -> PostgreSQL directement
```

## 4.5 Segmentation

Les réseaux doivent être séparés au minimum entre :

```text
Guest
Users
Servers
Management
```

Le réseau **Guest** ne doit avoir aucun accès aux serveurs ou ressources internes.

Les flux entre les différents réseaux doivent être limités par des règles firewall.

## 4.6 Ports réseau physiques

Les ports de switch inutilisés doivent être désactivés.

Seuls les ports nécessaires doivent être actifs.

Un équipement inconnu connecté physiquement dans les locaux ne doit pas automatiquement obtenir un accès aux ressources sensibles.

---

# 5. Journalisation

Les événements liés aux accès doivent être journalisés.

Cela comprend au minimum :

* connexions SSH ;
* échecs d'authentification ;
* utilisation de `sudo` ;
* connexions VPN ;
* modifications des comptes ;
* modifications des groupes ;
* changements de privilèges.

Les logs doivent être envoyés vers un serveur de journalisation centralisé afin qu'un attaquant ayant compromis un serveur ne puisse pas facilement supprimer toutes les traces de son activité.

---

# 6. Règles techniques principales

La future automatisation devra appliquer au minimum :

```text
1. Supprimer nexus_master.pem
2. Utiliser une clé SSH individuelle par utilisateur
3. Désactiver PasswordAuthentication
4. Désactiver PermitRootLogin
5. Créer des groupes RBAC
6. Limiter sudo selon les rôles
7. Bloquer PostgreSQL depuis Internet
8. Restreindre SSH au réseau d'administration/VPN
9. Désactiver les ports/services inutiles
10. Journaliser les accès et actions privilégiées
```

---

# 7. Conclusion

Cette politique remplace le modèle :

```text
Tout le monde -> clé partagée -> root -> production
```

par :

```text
Utilisateur identifié
        |
        v
Authentification individuelle
        |
        v
VPN / Réseau autorisé
        |
        v
RBAC
        |
        v
sudo limité
        |
        v
Ressource nécessaire
```

Cette architecture permet aux développeurs de continuer à travailler tout en appliquant **l'identification individuelle, le moindre privilège, la segmentation réseau et la traçabilité**.
