# Nexus Financial - Plan de Réponse aux Incidents

## Scénario : Base de données compromise

## 1. Objectif

Ce playbook définit la procédure à suivre lorsqu'une compromission de la base de données PostgreSQL de Nexus Financial est suspectée ou confirmée.

Les priorités sont :

* protéger les données ;
* limiter la propagation de l'attaque ;
* conserver les preuves ;
* restaurer les services de manière sécurisée ;
* comprendre la cause de l'incident ;
* éviter qu'il se reproduise.

---

# 2. Identification

L'objectif est de confirmer l'incident et d'évaluer son impact.

## Signes possibles

Les indicateurs peuvent inclure :

* connexions PostgreSQL provenant d'adresses IP inconnues ;
* nombreuses tentatives d'authentification ;
* comptes ou privilèges créés sans autorisation ;
* requêtes SQL inhabituelles ;
* modification ou suppression de données ;
* export massif de données ;
* activité réseau anormale sur le port `5432` ;
* alertes provenant de `rsyslog` ou `auditd`.

## Actions

1. Noter immédiatement la date et l'heure de détection.
2. Identifier le serveur concerné.
3. Identifier les comptes utilisés.
4. Rechercher les adresses IP suspectes.
5. Vérifier les logs PostgreSQL.
6. Vérifier les logs système et réseau.
7. Vérifier les événements `auditd`.
8. Déterminer si des données ont été consultées, modifiées ou supprimées.

Exemples :

```bash
journalctl -xe
```

```bash
ausearch -k privileged_commands
```

```bash
grep -i "failed" /var/log/auth.log
```

Les preuves doivent être conservées et ne doivent pas être modifiées ou supprimées.

---

# 3. Containment - Confinement

L'objectif est d'empêcher l'attaquant de continuer ses actions tout en conservant les éléments nécessaires à l'enquête.

## Confinement immédiat

Si une adresse IP malveillante est identifiée, la bloquer au niveau du firewall.

Exemple :

```bash
ufw deny from 203.0.113.50
```

Limiter immédiatement PostgreSQL au serveur Web autorisé :

```bash
ufw deny 5432/tcp
ufw allow from 10.0.1.10 to any port 5432 proto tcp
```

Vérifier les règles :

```bash
ufw status verbose
```

## Comptes compromis

Si un compte est compromis :

* désactiver le compte ;
* révoquer ses sessions ;
* révoquer ses clés SSH ;
* modifier les identifiants concernés ;
* rechercher l'utilisation du même secret sur d'autres systèmes.

La clé partagée `nexus_master.pem`, si elle existe encore, doit être immédiatement révoquée.

## Isolation

Si la compromission est importante, isoler le serveur concerné du reste du réseau.

Ne pas supprimer immédiatement les logs, fichiers suspects ou autres preuves.

---

# 4. Eradication

Une fois l'incident contenu, supprimer la cause de la compromission.

## Actions

Rechercher :

* comptes inconnus ;
* clés SSH non autorisées ;
* tâches cron suspectes ;
* processus inconnus ;
* services inconnus ;
* fichiers récemment modifiés ;
* logiciels malveillants ;
* modifications de configuration.

Exemples :

```bash
ps aux
```

```bash
ss -tulpn
```

```bash
crontab -l
```

```bash
find /etc -type f -mtime -7
```

```bash
find /home -name authorized_keys -type f
```

Supprimer les comptes, clés, services ou mécanismes de persistance identifiés comme malveillants.

Corriger la vulnérabilité utilisée pour l'intrusion.

PostgreSQL ne doit notamment plus être exposé à :

```text
0.0.0.0/0
```

Le port `5432` doit uniquement être accessible depuis les systèmes explicitement autorisés.

Les mots de passe, clés API, clés SSH et autres secrets potentiellement compromis doivent être renouvelés.

---

# 5. Recovery - Récupération

L'objectif est de restaurer les services sans réintroduire la compromission.

## Vérification des sauvegardes

Avant toute restauration :

* vérifier la date de la sauvegarde ;
* vérifier son intégrité ;
* vérifier qu'elle précède la compromission ;
* s'assurer qu'elle ne contient pas de modification malveillante.

Ne jamais restaurer automatiquement une sauvegarde dont l'intégrité est inconnue.

## Restauration

Si nécessaire :

1. reconstruire le serveur depuis une source fiable ;
2. appliquer les mises à jour de sécurité ;
3. appliquer `hardening.sh` ;
4. appliquer `rbac_setup.sh` ;
5. appliquer `network_defense.sh` ;
6. appliquer `logging_setup.sh` ;
7. restaurer une sauvegarde vérifiée ;
8. renouveler les secrets ;
9. tester l'application ;
10. remettre progressivement le service en production.

## Surveillance renforcée

Après la restauration, surveiller particulièrement :

* connexions PostgreSQL ;
* connexions SSH ;
* utilisation de `sudo` ;
* trafic réseau ;
* nouveaux comptes ;
* modifications de fichiers sensibles ;
* tentatives d'authentification.

La surveillance renforcée doit continuer jusqu'à ce que l'équipe ait suffisamment confiance dans l'intégrité du système.

---

# 6. Lessons Learned - Retour d'expérience

Après l'incident, Sarah, Dave et les responsables concernés doivent organiser une réunion de retour d'expérience.

Cette réunion ne doit pas chercher un responsable individuel mais identifier les défaillances techniques et organisationnelles.

Les questions suivantes doivent être traitées :

* Comment l'attaque a-t-elle commencé ?
* Quelle vulnérabilité a été exploitée ?
* Quand la compromission a-t-elle commencé ?
* Comment a-t-elle été détectée ?
* Quelles données ont été consultées, volées, modifiées ou supprimées ?
* Pourquoi les contrôles existants n'ont-ils pas empêché l'incident ?
* Les logs étaient-ils suffisants ?
* Les sauvegardes étaient-elles utilisables ?
* Le confinement a-t-il été suffisamment rapide ?
* Quelles mesures doivent être ajoutées ou améliorées ?

Un rapport d'incident doit ensuite documenter :

```text
Date et heure
Systèmes affectés
Méthode d'attaque
Comptes compromis
Données affectées
Actions de confinement
Actions d'éradication
Méthode de restauration
Cause racine
Mesures correctives
```

Les politiques, scripts et procédures de Nexus Financial doivent être mis à jour en fonction des conclusions.

---

# 7. Ordre de réponse

En cas de compromission confirmée de la base de données :

```text
DETECTION
    |
    v
IDENTIFICATION
    |
    v
CONFINEMENT
    |
    v
CONSERVATION DES PREUVES
    |
    v
ERADICATION
    |
    v
RESTAURATION
    |
    v
SURVEILLANCE
    |
    v
RETOUR D'EXPERIENCE
```

La priorité est de **contenir rapidement l'incident sans détruire les preuves**, puis de restaurer le service à partir d'un environnement dont l'intégrité a été vérifiée.
