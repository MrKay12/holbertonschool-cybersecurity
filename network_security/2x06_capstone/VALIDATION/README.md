# VALIDATION

Le dossier **VALIDATION** contient le script `tests.sh`, chargé de vérifier automatiquement que le bastion LogiCorp est conforme aux exigences de sécurité définies dans le projet.

Le script ne modifie jamais la configuration du système. Il réalise uniquement des contrôles et peut être exécuté après chaque modification afin de détecter rapidement toute régression de sécurité.

Toutes les vérifications utilisent la configuration centralisée définie dans :

```text
/etc/logicorp/hardening.conf
```

Aucune adresse IP, interface réseau ou port n'est codé en dur dans le script.

---

# Contenu

| Fichier | Description |
|----------|-------------|
| `tests.sh` | Vérifie automatiquement la conformité du pare-feu, des services, des contrôles d'accès et de la configuration réseau. |

---

# Configuration requise

Le script charge automatiquement le fichier :

```text
/etc/logicorp/hardening.conf
```

Un autre fichier peut être utilisé grâce à la variable d'environnement :

```bash
CONFIG_FILE=/chemin/vers/hardening.conf
```

Le fichier de configuration doit notamment contenir :

- les interfaces réseau ;
- les sous-réseaux ;
- les adresses IP ;
- les ports des services ;
- les utilisateurs autorisés à utiliser sudo ;
- les pairs WireGuard ;
- les serveurs applicatifs ;
- les réseaux privés ;
- les services devant être arrêtés.

---

# Vérifications effectuées

## Pare-feu

Le script contrôle automatiquement que :

- la politique par défaut de la chaîne **INPUT** est `DROP` ;
- la politique par défaut de la chaîne **FORWARD** est `DROP` ;
- les règles indispensables sont présentes ;
- les ensembles (`sets`) nftables sont correctement créés ;
- les règles d'accès SSH sont présentes ;
- les règles VPN sont présentes ;
- les règles FTP destinées au service Finance existent ;
- les règles NAT (Masquerade) sont présentes ;
- aucune règle `ACCEPT` inattendue n'a été ajoutée.

---

## SSH

Les vérifications comprennent :

- le service SSH est actif ;
- la configuration SSH est valide ;
- la connexion directe du compte root est désactivée ;
- seule l'authentification par clé publique est autorisée ;
- le groupe SSH autorisé est correctement configuré.

---

## VPN

Le script vérifie que :

- le service WireGuard est actif ;
- l'interface VPN est opérationnelle ;
- le port d'écoute est ouvert ;
- les pairs VPN sont correctement chargés ;
- les handshakes WireGuard sont valides (si cette vérification est activée).

---

## FTP

Le script vérifie que :

- le service FTP est actif ;
- le port FTP est en écoute ;
- les règles du pare-feu limitent correctement l'accès au serveur FTP ;
- seuls les utilisateurs Finance (LAN ou VPN) peuvent accéder au serveur FTP.

---

## Services

Le script contrôle :

- les services indispensables sont démarrés ;
- les services inutiles définis dans `hardening.conf` sont arrêtés.

---

## Contrôle des accès

Les vérifications portent sur :

- les utilisateurs autorisés à utiliser sudo ;
- l'absence d'utilisateurs sudo non autorisés.

---

## Configuration réseau

Le script vérifie :

- l'activation de l'IP Forwarding lorsqu'elle est requise ;
- l'existence des interfaces réseau ;
- l'adresse IP de chaque interface ;
- les routes vers les différents réseaux ;
- la route par défaut ;
- la route vers le serveur FTP ;
- la route vers la base de données.

---

# Format de sortie

Chaque contrôle retourne un résultat explicite.

Exemple :

```text
[PASS] Firewall default INPUT policy is DROP
[PASS] Firewall default FORWARD policy is DROP
[PASS] SSH service is running
[PASS] SSH root login is disabled
[PASS] SSH public key authentication is enabled
[PASS] VPN interface wg0 is UP
[PASS] Finance FTP rule exists
[FAIL] Unexpected ACCEPT rule detected

RESULT: 27/28 checks passed
```

---

# Code de retour

Le script retourne :

- **0** : toutes les vérifications sont réussies ;
- **1** : au moins une vérification a échoué.

Ce comportement permet son intégration dans des pipelines CI/CD, des scripts d'automatisation ou des tâches planifiées.

---

# Utilisation

Exécution avec la configuration par défaut :

```bash
sudo ./tests.sh
```

Utilisation d'un autre fichier de configuration :

```bash
sudo CONFIG_FILE=/chemin/vers/hardening.conf ./tests.sh
```

---

# Bonnes pratiques

Il est recommandé d'exécuter `tests.sh` :

- après toute modification du pare-feu ;
- après une modification de WireGuard ;
- après une mise à jour système ;
- après une modification de la configuration SSH ;
- avant une mise en production ;
- régulièrement via une tâche planifiée afin de détecter toute dérive de configuration.

---

# Objectif

`tests.sh` automatise les contrôles de conformité du bastion et garantit que la configuration reste conforme à l'architecture de sécurité définie pour le projet Capstone.

Cette approche applique les principes :

- **Infrastructure as Code**
- **Security as Code**
- **Compliance as Code**

en permettant de détecter rapidement toute régression de sécurité sans devoir réaliser des vérifications manuelles.