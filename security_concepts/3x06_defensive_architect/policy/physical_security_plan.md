# Nexus Financial - Plan de Sécurité Physique et Humaine

## 1. Objectif

Ce plan vise à protéger les locaux, les équipements et les employés de Nexus Financial contre les accès non autorisés, le vol, l'espionnage et les erreurs humaines.

Les mesures sont organisées selon leur priorité et leur coût.

---

## 2. Actions immédiates - 0 €

Ces actions doivent être appliquées immédiatement et ne nécessitent aucun investissement.

### Salle serveur "The Core"

* Retirer le bloque-porte et maintenir la salle fermée.
* Interdire l'accès aux visiteurs et livreurs.
* Limiter l'accès uniquement aux personnes autorisées.
* Déconnecter ou désactiver les ports réseau inutilisés.
* Interdire les photos et vidéos dans la salle serveur.
* Trouver temporairement une solution de ventilation sans laisser la porte ouverte.

### Postes de travail

* Verrouiller systématiquement les MacBooks lorsque les employés quittent leur bureau.
* Activer le verrouillage automatique après quelques minutes d'inactivité.
* Appliquer la règle : **un employé absent = un ordinateur verrouillé**.

### Informations sensibles

Effacer immédiatement du tableau blanc :

* le mot de passe Wi-Fi ;
* le mot de passe de la base de staging ;
* tous les autres identifiants ou secrets.

Les mots de passe ne doivent jamais être affichés dans un espace accessible aux visiteurs.

### Badges

* Retirer la boîte de badges située sous le bureau de l'Office Manager.
* Faire l'inventaire des badges existants.
* Identifier le propriétaire de chaque badge.
* Désactiver les badges perdus ou inutilisés.
* Interdire les badges génériques lorsque cela est possible.

---

## 3. Court terme - Faible coût

Ces mesures doivent être mises en place dans les semaines suivantes.

### Gestion des visiteurs

Mettre en place un registre simple des visiteurs comprenant :

* nom ;
* entreprise ;
* personne visitée ;
* heure d'arrivée ;
* heure de départ.

Chaque visiteur doit être accompagné par un employé dans les zones internes.

### Badges visiteurs

Créer quelques badges clairement identifiés :

`VISITOR 01`, `VISITOR 02`, etc.

Ils doivent être rendus lors du départ du visiteur.

### Salle serveur

Mettre en place :

* une liste des personnes autorisées ;
* un registre des accès ;
* une signalétique **"Accès réservé au personnel autorisé"** ;
* une solution correcte de ventilation/climatisation ;
* un rangement correct des câbles et équipements.

### Réseau

Les prises et ports réseau inutilisés doivent être désactivés.

Un visiteur branchant son ordinateur sur une prise libre ne doit pas pouvoir accéder directement au réseau interne de l'entreprise.

### Protection des écrans

Configurer automatiquement :

* verrouillage après une courte période d'inactivité ;
* authentification obligatoire après verrouillage ;
* mises à jour de sécurité automatiques.

---

## 4. Long terme

Lorsque le budget le permettra, Nexus Financial devra améliorer durablement sa sécurité physique.

### Contrôle d'accès

Mettre en place des badges individuels permettant :

* d'identifier chaque utilisateur ;
* de contrôler les zones accessibles ;
* de désactiver rapidement un badge ;
* de conserver un historique des accès.

### Salle serveur

La salle serveur doit devenir une zone réellement sécurisée avec :

* accès limité ;
* porte toujours verrouillée ;
* climatisation adaptée ;
* détection incendie ;
* capteurs de température ;
* surveillance des accès.

### Vidéosurveillance

Installer des caméras dans les zones sensibles, notamment :

* entrée des locaux ;
* accès à la salle serveur.

La vidéosurveillance doit respecter la réglementation applicable et ne doit pas surveiller inutilement les postes de travail des employés.

### Gestion centralisée des appareils

Mettre en place une solution MDM pour gérer les MacBooks de l'entreprise et imposer :

* verrouillage automatique ;
* chiffrement du disque ;
* politique de mots de passe ;
* mises à jour ;
* possibilité d'effacement à distance en cas de perte ou de vol.

---

## 5. Formation et sensibilisation

La sécurité physique dépend également du comportement des employés.

Une courte formation obligatoire doit expliquer :

* pourquoi verrouiller son ordinateur ;
* pourquoi ne jamais partager ou afficher un mot de passe ;
* comment gérer les visiteurs ;
* pourquoi les badges ne doivent pas être prêtés ;
* comment signaler une personne suspecte ;
* pourquoi les photos et vidéos peuvent révéler des informations sensibles.

### Incident du livreur TikTok

Le livreur présent dans la salle serveur ne doit pas être considéré uniquement comme un problème individuel. Il démontre une défaillance du contrôle des visiteurs.

La réponse doit être :

1. Faire sortir immédiatement le visiteur de la zone sécurisée.
2. Demander l'arrêt de toute photo ou vidéo.
3. Vérifier si des équipements, écrans, câbles, documents ou informations sensibles ont été filmés.
4. Signaler et documenter l'incident.
5. Si la vidéo a été publiée, demander son retrait.
6. Vérifier les accès et secrets potentiellement exposés et les changer si nécessaire.
7. Expliquer aux employés qu'un visiteur ne doit jamais circuler seul dans une zone sensible.

L'objectif n'est pas de sanctionner automatiquement un employé, mais de corriger le processus qui a permis à un visiteur d'accéder librement à la salle serveur.

---

## 6. Priorités

Dans les cinq jours précédant l'audit, Nexus Financial doit en priorité :

**Fermer la salle serveur → contrôler les visiteurs → supprimer les secrets visibles → verrouiller les postes → contrôler les badges → désactiver les ports réseau inutilisés.**

Ces mesures sont simples et peu coûteuses mais réduisent immédiatement plusieurs risques critiques identifiés dans le modèle de menaces.
