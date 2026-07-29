# Executive Summary

Sur la base de la documentation fournie et des preuves collectées lors de l'audit technique, l'infrastructure de LogiCorp présente plusieurs faiblesses de sécurité critiques qui ont probablement contribué à la récente attaque par ransomware.

L'audit confirme notamment l'absence de segmentation réseau, l'exposition de services d'administration, l'autorisation de la connexion SSH de **root**, l'utilisation d'un service FTP non chiffré et la présence de données sensibles stockées en clair.

De nouvelles preuves techniques ont également permis de confirmer ou d'identifier :

- des journaux contenant une connexion SSH réussie avec le compte **root**, dont certaines entrées sont générées par le script d'initialisation de l'environnement de laboratoire ;
- un accès FTP anonyme activé ;
- les opérations d'écriture autorisées sur le service FTP ;
- une tâche planifiée exécutée chaque minute avec les privilèges **root** ;
- un mot de passe administrateur enregistré en clair dans une sauvegarde ;
- l'exposition de services supplémentaires d'administration et de développement ;
- la présence de mécanismes de détection, sans preuve suffisante de leur fonctionnement effectif en continu.

Une refonte complète de l'architecture de sécurité, fondée sur les principes du **Zero Trust**, reste recommandée tout en garantissant la continuité des activités.

# Évaluation de l'état actuel

La documentation et l'audit technique décrivent l'infrastructure suivante :

- Une unique passerelle Linux assure la connectivité entre le WAN et le LAN.
- L'ensemble du réseau interne repose sur une architecture plate.
- Les postes bureautiques, les systèmes de la Finance, le Wi-Fi invité et la base de données critique partagent le même environnement réseau.
- Le service SSH écoute sur toutes les interfaces IPv4 et IPv6.
- La connexion SSH avec le compte **root** est autorisée et une authentification réussie a été enregistrée.
- Un serveur **vsftpd** écoute sur le port TCP `21`.
- Le service FTP fonctionne sans chiffrement TLS.
- L'accès FTP anonyme est activé.
- Les opérations d'écriture FTP sont autorisées.
- Des services supplémentaires sont exposés sur les ports TCP `3000` et `3001`.
- Une tâche cron exécutée par **root** contacte chaque minute l'adresse `192.168.1.200`.
- Une sauvegarde contient un mot de passe administrateur en clair.
- La base de données est référencée à l'adresse `192.168.1.50`.
- La présence d'une politique de pare-feu active n'a pas pu être confirmée avec les privilèges disponibles pendant l'audit.
- Aucune redondance n'est mise en place (hors du périmètre du présent projet).

Les conclusions suivantes reposent donc sur la combinaison de la documentation fournie et des preuves techniques collectées sur l'environnement.

# Principales failles de sécurité identifiées

## 1. Architecture réseau

### État actuel

**Preuves utilisées :**
- `audit_evidence/02_network/`
- `audit_evidence/01_system/`

- Architecture réseau plate (*Flat Network*).
- Absence de segmentation confirmée par la configuration :

```text
NETWORK_MODE=FLAT
```

- La base de données est référencée directement sur le réseau interne :

```text
DB_HOST=192.168.1.50
DB_PORT=3306
```

- Aucun isolement technique de la base de données, du réseau Finance ou du Wi-Fi invité n'a été mis en évidence.

### État cible

- Réseau segmenté conformément aux principes du **Zero Trust**.
- Création de zones de sécurité distinctes pour :
  - WAN
  - LAN bureautique
  - Finance
  - DMZ
  - Serveurs critiques
  - Administration
  - Réseau invité
- Filtrage strict des communications entre les zones.
- Accès à la base de données limité aux seuls systèmes autorisés.

### Écart identifié

L'absence de segmentation permet des déplacements latéraux sans restriction. Un équipement compromis sur le réseau invité ou bureautique pourrait atteindre les systèmes critiques et la base de données.

> **Niveau de risque : Critique**

---

## 2. Contrôle des accès

### État actuel

**Preuves utilisées :**
- `audit_evidence/06_ssh/ssh_configuration.txt`
- `audit_evidence/06_ssh/ssh_security_values.txt`
- `audit_evidence/11_logs/`

- SSH écoute sur toutes les interfaces :

```text
0.0.0.0:22
[::]:22
```

- La connexion directe de **root** est autorisée.
- Les journaux contiennent plusieurs tentatives d'authentification échouées :

```text
Failed password for root from 10.10.10.10
Failed password for invalid user admin from 10.10.10.66
```

- Une connexion réussie avec le compte **root** est également présente dans les journaux :

```text
Accepted password for root from 192.168.1.99
```

- Aucun accès administratif exclusivement limité à un VPN n'a été confirmé.

### État cible

- Accès administratifs uniquement via un VPN chiffré.
- Désactivation de la connexion SSH directe de **root**.
- Désactivation de l'authentification SSH par mot de passe lorsque cela est possible.
- Utilisation de comptes administratifs nominatifs et de clés SSH.
- Application du principe du moindre privilège.
- Restriction des adresses sources autorisées à joindre SSH.

### Écart identifié

Les services d'administration sont exposés sur toutes les interfaces et la connexion directe du compte **root** est autorisée. Les journaux contiennent une authentification réussie, mais l'analyse du script `/etc/run.sh` montre que certaines entrées sont générées artificiellement par l'environnement de laboratoire. Cette trace ne peut donc pas être considérée, à elle seule, comme une preuve de compromission réelle. En revanche, l'autorisation de connexion du compte **root** constitue une vulnérabilité critique.

> **Niveau de risque : Critique**

---

## 3. Chiffrement des communications et sécurité FTP

### État actuel

**Preuves utilisées :**
- `audit_evidence/09_ftp/ftp_configuration.txt`
- `audit_evidence/09_ftp/ftp_effective_security.txt`
- `audit_evidence/09_ftp/ftp_security_findings.txt`

Le serveur **vsftpd** est actif et écoute sur le port TCP `21`.

Les paramètres de configuration collectés indiquent :

```text
anonymous_enable=YES
local_enable=YES
write_enable=YES
ssl_enable=NO
```

La configuration contient deux valeurs pour `anonymous_enable`, mais la dernière directive active est `anonymous_enable=YES`. Elle autorise donc l'accès anonyme.

Le répertoire FTP contient également un fichier indiquant son usage pour les factures Finance :

```text
Finance invoices here
```

### État cible

- Remplacement de FTP par **SFTP** ou **FTPS**.
- À défaut, accès au service FTP uniquement à travers un VPN.
- Activation obligatoire du chiffrement des flux de contrôle et de données.
- Désactivation de l'accès anonyme.
- Restriction stricte des droits d'écriture.
- Isolement du service dans une DMZ ou une zone Finance dédiée.
- Journalisation complète des connexions et transferts.

### Écart identifié

Les identifiants et les données sont transmis en clair. L'accès anonyme et les droits d'écriture augmentent également les risques d'accès non autorisé, de dépôt de fichiers malveillants, d'altération ou d'exfiltration de données.

> **Niveau de risque : Critique**

---

## 4. Supervision, surveillance et protection périmétrique

### État actuel

**Preuves utilisées :**
- `audit_evidence/04_security_controls/`
- `audit_evidence/11_logs/`

- La présence de règles `nftables` n'a pas pu être vérifiée, la commande ayant retourné :

```text
Operation not permitted (you must be root)
```

- La commande `iptables` n'est pas disponible.
- Une configuration Fail2Ban pour SSH est présente :

```text
[sshd]
enabled = true
```

- Des fichiers de configuration et de règles Suricata sont présents.
- Un indicateur de détection IDS a été trouvé dans les journaux.
- Aucun processus Suricata actif n'a toutefois été confirmé pendant la collecte.
- La présence de fichiers de configuration ne suffit pas à confirmer que Fail2Ban ou Suricata fonctionnent correctement et en continu.

### État cible

- Politique de pare-feu **Deny by Default**.
- Vérification et sauvegarde des règles de filtrage actives.
- Fail2Ban actif et testé sur les services exposés.
- IDS/IPS actif, supervisé et alimenté avec des règles à jour.
- Journalisation centralisée des événements de sécurité.
- Alertes sur les connexions administratives, les échecs répétés et les modifications de configuration.
- Traçabilité complète des accès administratifs.

### Écart identifié

Des mécanismes de sécurité semblent être configurés, mais leur état opérationnel n'est pas suffisamment démontré. La protection périmétrique active reste également non confirmée. Les contrôles doivent être testés en conditions réelles et surveillés en continu.

> **Niveau de risque : Élevé**

---

## 5. Tâches planifiées et mécanisme de persistance

### État actuel

**Preuves utilisées :**
- `audit_evidence/08_persistence/cron_system.txt`
- `audit_evidence/08_persistence/`

Une tâche cron non documentée est exécutée chaque minute avec les privilèges **root** :

```text
* * * * * root /usr/bin/curl http://192.168.1.200/ping
```

Les processus observés confirment l'exécution effective de cette commande :

```text
/bin/sh -c /usr/bin/curl http://192.168.1.200/ping
/usr/bin/curl http://192.168.1.200/ping
```

### État cible

- Inventaire complet des tâches planifiées.
- Validation formelle de chaque tâche exécutée avec des privilèges élevés.
- Suppression des tâches non autorisées.
- Blocage des communications sortantes non nécessaires.
- Alertes lors de la création ou de la modification d'une tâche cron.
- Contrôle d'intégrité des fichiers sous `/etc/cron.d`.

### Écart identifié

Cette tâche établit une communication sortante répétée avec une adresse interne et s'exécute avec les privilèges les plus élevés. En l'absence d'informations sur son objectif métier, elle constitue un mécanisme de persistance potentiel qui nécessite une investigation complémentaire avant d'être qualifiée de comportement malveillant.

> **Niveau de risque : Critique**

---

## 6. Protection des données sensibles et des sauvegardes

### État actuel

**Preuves utilisées :**
- `audit_evidence/10_sensitive_data/`

Une sauvegarde lisible contient un mot de passe administrateur en clair :

```text
root_password_backup=123456
```

Le fichier concerné est situé dans :

```text
/opt/logicorp/backups/backup.sql
```

### État cible

- Aucun mot de passe en clair dans les fichiers ou sauvegardes.
- Utilisation d'un coffre-fort de secrets.
- Chiffrement des sauvegardes au repos.
- Permissions limitées aux seuls comptes de service autorisés.
- Rotation immédiate des secrets exposés.
- Analyse automatique des sauvegardes afin de détecter les secrets.

### Écart identifié

Toute personne capable de lire cette sauvegarde peut récupérer un mot de passe administrateur. Cette exposition facilite une élévation de privilèges et peut permettre une compromission complète du système.

> **Niveau de risque : Critique**

---

## 7. Services exposés et outils d'administration supplémentaires

### État actuel

**Preuves utilisées :**
- `audit_evidence/03_attack_surface/`
- `audit_evidence/07_services/`

Les ports suivants sont ouverts :

```text
21/tcp    FTP
22/tcp    SSH
3000/tcp  OpenVSCode Server
3001/tcp  ttyd
```

Les processus collectés montrent notamment :

```text
ttyd --cwd /root --writable ... -p 3001 /bin/bash
openvscode-server --host 0.0.0.0 ...
```

Le service `ttyd` fournit un terminal Bash accessible à distance et configuré avec un répertoire de travail sous `/root`. OpenVSCode écoute également sur toutes les interfaces.

### État cible

- Suppression de tout outil d'administration non nécessaire.
- Interdiction d'exposer un terminal Web ou un environnement de développement sur une passerelle.
- Accès aux outils d'administration uniquement depuis un réseau dédié ou un VPN.
- Écoute sur une interface d'administration spécifique.
- Authentification forte et rotation des jetons d'accès.
- Inventaire et validation de chaque service exposé.

### Écart identifié

Ces services fournissent des interfaces puissantes pouvant faciliter l'exécution de commandes et la modification de fichiers. Leur exposition sur toutes les interfaces augmente fortement la surface d'attaque de la passerelle.

> **Niveau de risque : Critique**

# Matrice des risques

| Faiblesse de sécurité | Gravité | Preuve principale | Impact métier |
|------------------------|:-------:|-------------------|---------------|
| Réseau plat / Absence de segmentation | 🔴 Critique | `NETWORK_MODE=FLAT` | Facilite les déplacements latéraux vers les systèmes critiques |
| Base de données non isolée | 🔴 Critique | `DB_HOST=192.168.1.50` | Risque de compromission ou d'exfiltration des données |
| SSH exposé sur toutes les interfaces | 🔴 Critique | `0.0.0.0:22` et `[::]:22` | Risque d'accès administratif non autorisé |
| Connexion root autorisée et observée | 🔴 Critique | `Accepted password for root` | Compromission complète du système |
| Protection par pare-feu non confirmée | 🟠 Élevée | Accès `nftables` refusé, `iptables` absent | Filtrage du trafic impossible à valider |
| FTP sans TLS | 🔴 Critique | `ssl_enable=NO` | Interception des identifiants et des données |
| Accès FTP anonyme | 🔴 Critique | `anonymous_enable=YES` | Accès non autorisé aux ressources FTP |
| Écriture FTP autorisée | 🟠 Élevée | `write_enable=YES` | Dépôt ou altération de fichiers |
| Tâche cron root non documentée | 🔴 Critique | `curl http://192.168.1.200/ping` chaque minute | Persistance ou communication de commande et contrôle |
| Mot de passe root stocké en clair | 🔴 Critique | `root_password_backup=123456` | Vol d'identifiants et élévation de privilèges |
| Terminal Web ttyd exposé | 🔴 Critique | Port `3001`, Bash sous `/root` | Exécution distante de commandes |
| OpenVSCode exposé | 🔴 Critique | Port `3000`, écoute sur `0.0.0.0` | Modification de fichiers ou exécution de code |
| Absence de VPN administratif confirmé | 🟠 Élevée | Administration directe via SSH | Surface d'attaque accrue |
| Contrôles IDS/anti-bruteforce non pleinement validés | 🟠 Élevée | Configurations présentes, fonctionnement continu non confirmé | Détection ou blocage potentiellement incomplets |
| Absence de procédure d'audit documentée | 🟡 Moyenne | Écart entre documentation et environnement réel | Visibilité opérationnelle réduite |
| Point de défaillance unique | 🟡 Moyenne | Passerelle Linux unique | Risque sur la disponibilité, hors périmètre du projet |

---


# Analyse des preuves collectées

Les preuves techniques ont été classées en trois catégories.

## Vulnérabilités confirmées

- Réseau plat sans segmentation.
- Connexion SSH directe du compte **root** autorisée.
- Service FTP sans chiffrement TLS, avec accès anonyme et droits d'écriture.
- Exposition des services `ttyd` et `OpenVSCode`.
- Présence d'un mot de passe administrateur en clair dans une sauvegarde.

## Éléments simulés par l'environnement de laboratoire

L'analyse du script `/etc/run.sh` montre que certaines entrées des journaux d'authentification et certains événements de détection sont générés automatiquement afin de simuler des incidents de sécurité. Ces éléments ont été identifiés et ne sont pas considérés, à eux seuls, comme des preuves d'une compromission réelle.

## Éléments nécessitant une investigation complémentaire

- Tâche cron exécutée chaque minute avec les privilèges **root**.
- Finalité des services `ttyd` et `OpenVSCode`.
- Vérification des règles de pare-feu actives avec des privilèges administrateur.
- Validation du fonctionnement effectif de Fail2Ban et Suricata.


# Recommandations préliminaires

Sur la base de la documentation et des preuves techniques collectées, les actions prioritaires suivantes sont recommandées :

1. Isoler immédiatement ou désactiver les services `ttyd` et OpenVSCode exposés sur les ports `3001` et `3000`.
2. Supprimer ou désactiver la tâche cron qui contacte `192.168.1.200` après avoir conservé les preuves nécessaires à l'investigation.
3. Modifier immédiatement le mot de passe exposé dans `backup.sql`, rechercher ses éventuelles réutilisations et supprimer le secret du fichier.
4. Désactiver la connexion SSH directe de **root**.
5. Restreindre SSH à un VPN WireGuard et à des comptes administratifs nominatifs.
6. Déployer ou confirmer une politique de pare-feu **Deny by Default** avec `nftables`.
7. Désactiver l'accès FTP anonyme et les droits d'écriture non nécessaires.
8. Remplacer FTP par SFTP ou FTPS ; à défaut, limiter son accès au VPN et à une zone Finance isolée.
9. Mettre en œuvre une architecture réseau **Zero Trust** avec des zones dédiées au réseau invité, à la Finance, aux postes bureautiques, à l'administration et aux serveurs critiques.
10. Restreindre l'accès à la base de données aux seules applications autorisées.
11. Vérifier que Fail2Ban et Suricata sont réellement actifs, correctement configurés, testés et supervisés.
12. Centraliser les journaux d'authentification, de pare-feu, FTP, SSH, cron et IDS.
13. Mettre en place un contrôle d'intégrité sur les fichiers de configuration, les tâches cron et les fichiers sensibles.
14. Chiffrer les sauvegardes et limiter leurs permissions.
15. Valider l'ensemble des contrôles à l'aide de tests automatisés de conformité avant la mise en production.

---

# Hypothèses et limites

Cette évaluation repose sur la documentation fournie par LogiCorp et sur les preuves collectées par le script d'audit technique.

L'environnement audité est un environnement pédagogique. L'analyse du script `/etc/run.sh` a montré que certaines traces présentes dans les journaux sont générées automatiquement afin de simuler des événements de sécurité. Ces éléments ont été distingués des vulnérabilités réellement observées lors de l'audit.

Certaines limitations subsistent :

- l'audit a été exécuté sans privilèges suffisants pour afficher les règles `nftables` ;
- l'absence de sortie exploitable ne permet donc pas de conclure définitivement à l'absence de pare-feu ;
- la présence de configurations Fail2Ban et Suricata ne confirme pas à elle seule leur fonctionnement continu ;
- aucun test d'intrusion actif n'a été réalisé ;
- aucun changement de configuration n'a été effectué pendant la collecte ;
- l'étendue exacte de l'exposition externe dépend des équipements réseau situés en amont de la passerelle.

La prochaine étape de la mission consistera à :

- exécuter les contrôles nécessitant des privilèges administrateur ;
- confirmer les règles de pare-feu réellement chargées ;
- vérifier l'état opérationnel de Fail2Ban et Suricata ;
- analyser l'origine et la finalité de la tâche cron ;
- vérifier les journaux de connexion de `ttyd`, OpenVSCode, SSH et FTP ;
- rechercher toute réutilisation du mot de passe exposé ;
- identifier les services non documentés ;
- affiner le plan de remédiation en fonction des constats techniques.
