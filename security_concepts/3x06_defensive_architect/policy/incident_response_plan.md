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

# 2. Contacts et Escalade

## Équipe de réponse aux incidents

| Rôle                | Responsable                  | Responsabilité                                      |
| ------------------- | ---------------------------- | --------------------------------------------------- |
| Incident Commander  | Sarah - Lead Developer       | Coordination technique de l'incident                |
| Direction technique | Dave - CTO                   | Décisions techniques et métier                      |
| Direction           | CEO                          | Décisions critiques et communication exécutive      |
| Sécurité            | Interim CISO / Security Team | Investigation, confinement et coordination sécurité |
| Juridique           | Legal Team                   | Obligations légales et réglementaires               |
| Communication       | PR / Communication Team      | Communication externe                               |

Les coordonnées téléphoniques et adresses email professionnelles doivent être conservées dans l'annuaire d'urgence interne de Nexus Financial et accessibles même si les systèmes principaux sont indisponibles.

## Niveaux d'escalade

### P1 - Faible

Exemple :

* tentative d'accès bloquée ;
* aucune donnée compromise ;
* aucun service critique affecté.

Informer l'équipe Security et documenter l'événement.

### P2 - Important

Exemple :

* activité suspecte confirmée ;
* compte utilisateur potentiellement compromis ;
* accès non autorisé possible.

Sarah et Dave doivent être informés rapidement et une investigation doit commencer.

### P0 - Critique

Une compromission confirmée ou probable de la base de données de production est un incident **P0**.

Exemples :

* accès non autorisé à la base ;
* extraction de données ;
* modification ou suppression de données ;
* compte administrateur compromis ;
* présence confirmée d'un attaquant.

Escalade immédiate vers :

1. Incident Commander ;
2. CTO ;
3. Security / CISO ;
4. CEO ;
5. équipe juridique si des données sont concernées.

L'incident doit être traité immédiatement.

## Contacts externes

Selon la nature et l'impact de l'incident, l'équipe juridique et la direction déterminent s'il est nécessaire de contacter :

* l'assureur cyber ;
* le prestataire Cloud ;
* les partenaires concernés ;
* les autorités compétentes ;
* les forces de l'ordre ;
* les personnes ou clients concernés.

Toute notification réglementaire doit respecter les délais et obligations applicables.

---

# 3. Identification

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
2. Informer l'Incident Commander.
3. Identifier le serveur concerné.
4. Identifier les comptes utilisés.
5. Rechercher les adresses IP suspectes.
6. Vérifier les logs PostgreSQL.
7. Vérifier les logs système et réseau.
8. Vérifier les événements `auditd`.
9. Déterminer si des données ont été consultées, modifiées ou supprimées.
10. Déterminer le niveau d'escalade P1, P2 ou P0.

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

# 4. Containment - Confinement

L'objectif est d'empêcher l'attaquant de continuer ses actions tout en conservant les éléments nécessaires à l'enquête.

## Confinement immédiat

Si une adresse IP malveillante est identifiée :

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
* rechercher le même secret sur les autres systèmes.

La clé partagée `nexus_master.pem`, si elle existe encore, doit être immédiatement révoquée.

## Isolation

Si la compromission est importante, isoler le serveur concerné du reste du réseau.

Ne pas supprimer les logs, fichiers suspects ou autres preuves nécessaires à l'investigation.

---

# 5. Eradication

Une fois l'incident contenu, supprimer la cause de la compromission.

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

PostgreSQL ne doit plus être exposé à :

```text
0.0.0.0/0
```

Le port `5432` doit uniquement être accessible depuis les systèmes explicitement autorisés.

Tous les secrets potentiellement compromis doivent être renouvelés :

* mots de passe ;
* clés SSH ;
* clés API ;
* tokens ;
* identifiants de base de données.

---

# 6. Recovery - Récupération

L'objectif est de restaurer les services sans réintroduire la compromission.

## Vérification des sauvegardes

Avant toute restauration :

* vérifier la date de la sauvegarde ;
* vérifier son intégrité ;
* vérifier qu'elle précède la compromission ;
* vérifier qu'elle ne contient pas de modification malveillante.

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

Après restauration, surveiller :

* connexions PostgreSQL ;
* connexions SSH ;
* utilisation de `sudo` ;
* trafic réseau ;
* nouveaux comptes ;
* modifications de fichiers sensibles ;
* tentatives d'authentification.

---

# 7. Communication

Pendant un incident P0, une communication claire doit être maintenue.

## Message interne

Exemple :

> INCIDENT P0 - Une compromission potentielle de la base de données de production a été détectée. L'équipe de réponse aux incidents est activée. Ne modifiez pas les systèmes concernés sans autorisation de l'Incident Commander.

Les employés ne doivent pas communiquer publiquement sur l'incident.

Toute communication externe doit être validée par la direction, l'équipe juridique et l'équipe communication.

Les informations suivantes doivent être communiquées aux responsables :

* heure de détection ;
* systèmes concernés ;
* impact connu ;
* actions de confinement réalisées ;
* données potentiellement concernées ;
* prochaines actions prévues.

---

# 8. Lessons Learned - Retour d'expérience

Après l'incident, Sarah, Dave, Security et les responsables concernés doivent organiser une réunion de retour d'expérience.

Les questions suivantes doivent être traitées :

* Comment l'attaque a-t-elle commencé ?
* Quelle vulnérabilité a été exploitée ?
* Quand la compromission a-t-elle commencé ?
* Comment a-t-elle été détectée ?
* Quelles données ont été affectées ?
* Pourquoi les contrôles existants n'ont-ils pas empêché l'incident ?
* Les logs étaient-ils suffisants ?
* Les sauvegardes étaient-elles utilisables ?
* Le confinement a-t-il été suffisamment rapide ?
* Quelles mesures doivent être améliorées ?

Un rapport doit documenter :

```text
Date et heure
Niveau de gravité
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

Les politiques, scripts et procédures doivent ensuite être mis à jour.

---

# 9. Cycle de réponse

```text
ALERTE
   |
   v
IDENTIFICATION
   |
   v
ESCALADE
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
RECUPERATION
   |
   v
SURVEILLANCE
   |
   v
RETOUR D'EXPERIENCE
```

En cas de compromission de la base de données, la priorité est de **déclencher rapidement l'escalade, contenir l'attaque, préserver les preuves et restaurer le service depuis un environnement fiable**.
