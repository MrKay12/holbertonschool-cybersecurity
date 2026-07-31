# DEFENSE

# Défense des choix d'architecture

Ce document présente les justifications techniques et métier des choix réalisés lors de la sécurisation de l'infrastructure LogiCorp.

L'objectif n'était pas uniquement de renforcer la sécurité, mais également de respecter les contraintes opérationnelles de l'entreprise tout en garantissant la continuité de service.

---

# Challenge 1 : Maintien du service FTP

## Pourquoi avoir conservé FTP ?

Le protocole FTP est effectivement considéré comme obsolète d'un point de vue sécurité.

Cependant, la mission imposait explicitement de maintenir le fonctionnement du service FTP utilisé par le service Finance.

Le remplacement immédiat par SFTP ou FTPS aurait nécessité :

- la modification des applications métiers ;
- une adaptation des procédures internes ;
- des tests de compatibilité ;
- une période de migration.

Ces éléments dépassaient le périmètre du projet.

L'objectif était donc de sécuriser l'environnement existant sans interrompre l'activité de l'entreprise.

---

## Mesures de réduction des risques

Afin de limiter les risques liés à FTP, plusieurs protections ont été mises en place.

### Isolation réseau

Le serveur FTP est isolé dans une zone dédiée.

Seul le VLAN Finance peut accéder au serveur FTP.

Les autres VLAN n'ont aucun accès au service.

---

### Accès distant sécurisé

Les collaborateurs distants ne peuvent plus accéder directement au serveur.

Ils doivent :

- établir une connexion WireGuard ;
- être identifiés comme utilisateurs Finance ;
- accéder ensuite au serveur FTP via le tunnel VPN.

FTP n'est donc jamais exposé directement sur Internet.

---

### Filtrage du pare-feu

Le pare-feu nftables autorise uniquement :

- Finance → FTP
- VPN Finance → FTP

Toutes les autres communications sont bloquées par défaut.

---

### Réduction de la surface d'attaque

Le serveur FTP n'est plus accessible :

- depuis Internet ;
- depuis le réseau Invités ;
- depuis les postes bureautiques ;
- depuis les autres VLAN internes.

La surface d'exposition est donc fortement réduite.

---

## Risques résiduels

Malgré ces protections, FTP reste un protocole non chiffré.

Les identifiants et les données circulent en clair entre le poste client et le serveur FTP.

Ce risque est toutefois limité par le fait que :

- les communications passent dans un tunnel WireGuard lorsqu'elles proviennent de l'extérieur ;
- l'accès interne est limité exclusivement au réseau Finance.

Le risque résiduel est donc accepté afin de respecter les contraintes métier.

---

## Recommandation pour une Phase 2

À moyen terme, il est recommandé de remplacer complètement FTP par un protocole sécurisé.

Les solutions privilégiées seraient :

- SFTP (SSH File Transfer Protocol)
- FTPS (FTP over TLS)

Cette évolution supprimerait définitivement les échanges en clair tout en conservant les fonctionnalités métier.

---

# Challenge 2 : Stratégie de segmentation

## Principe retenu

L'infrastructure d'origine utilisait un réseau plat.

Tous les équipements partageaient le même domaine réseau, permettant à un attaquant de se déplacer librement après une compromission.

La nouvelle architecture applique une segmentation réseau basée sur le principe du moindre privilège.

Chaque zone possède un niveau de confiance différent.

---

## Définition des zones

### WAN

Connexion vers Internet.

Aucune confiance.

---

### VPN

Zone réservée aux utilisateurs authentifiés via WireGuard.

Accès limité selon le rôle de l'utilisateur.

---

### Management

Administration de l'infrastructure.

Accès réservé aux administrateurs.

---

### Office

Postes utilisateurs.

Accès limité aux seuls services nécessaires.

---

### Finance

Service utilisant le serveur FTP.

Accès autorisé uniquement vers les ressources indispensables.

---

### DMZ

Serveurs accessibles depuis plusieurs zones.

Isolation des services exposés.

---

### Serveurs

Base de données et services applicatifs.

Aucun accès direct depuis les postes utilisateurs.

---

### Guest

Réseau visiteurs.

Aucun accès aux ressources internes.

Uniquement un accès Internet.

---

## Restrictions de circulation

Toutes les communications sont bloquées par défaut.

Chaque flux autorisé est explicitement déclaré dans le pare-feu.

Exemples :

- VPN Admin → Administration
- Finance → FTP
- VPN Finance → FTP
- Serveurs applicatifs → Base de données
- Guest → Internet

Tout autre trafic est refusé.

---

## Blocage du scénario d'attaque précédent

Lors de l'incident initial, la compromission d'un poste permettait à l'attaquant de parcourir librement le réseau interne.

Avec la nouvelle architecture :

- les VLAN sont isolés ;
- le pare-feu filtre les communications entre zones ;
- les serveurs critiques ne sont accessibles qu'aux équipements autorisés ;
- les réseaux Invités et utilisateurs ne peuvent plus atteindre directement les ressources sensibles.

La compromission d'un poste utilisateur ne permet donc plus de progresser automatiquement vers les serveurs critiques.

Les déplacements latéraux sont fortement limités.

---

## Défense en profondeur

La stratégie repose sur plusieurs couches de sécurité.

- segmentation réseau ;
- pare-feu nftables ;
- VPN WireGuard ;
- durcissement SSH ;
- suppression des services inutiles ;
- limitation des privilèges ;
- validation automatique de la configuration.

La compromission d'un mécanisme ne compromet plus l'ensemble de l'infrastructure.

---

# Challenge 3 : Résilience

## Point de défaillance unique

Le Gateway reste un point de défaillance unique.

En cas de panne :

- les communications entre VLAN cessent ;
- les connexions VPN deviennent indisponibles ;
- le filtrage réseau disparaît ;
- l'accès Internet est interrompu.

Cette situation est connue.

---

## Justification

La haute disponibilité ne faisait pas partie du périmètre du projet.

Les objectifs étaient :

- sécuriser l'infrastructure ;
- réduire la surface d'attaque ;
- limiter les mouvements latéraux ;
- maintenir les services existants.

La mise en place d'une architecture redondante aurait nécessité des équipements supplémentaires ainsi qu'une refonte de l'infrastructure.

---

## Risque actuel

Le risque principal est une indisponibilité temporaire des services en cas de défaillance matérielle du Gateway.

En revanche, cette panne n'entraîne pas une perte de confidentialité ou d'intégrité des données.

Le risque est donc essentiellement opérationnel.

---

## Proposition pour une Phase 2

Une évolution naturelle consisterait à mettre en place une architecture haute disponibilité comprenant :

- deux passerelles ;
- synchronisation de la configuration ;
- basculement automatique (VRRP/CARP) ;
- redondance WireGuard ;
- alimentation redondante ;
- supervision de l'état des équipements.

Cette architecture permettrait d'assurer la continuité de service même en cas de panne d'une passerelle.

---

## Analyse coût / bénéfice

La mise en place d'une haute disponibilité représente un investissement matériel et humain important.

Au regard des objectifs du projet, le renforcement de la sécurité apportait un bénéfice immédiat beaucoup plus important que la mise en place d'une redondance.

Le choix réalisé permet donc d'améliorer significativement le niveau de sécurité tout en maîtrisant les coûts et en respectant le périmètre du projet.

---

# Conclusion

Les choix réalisés résultent d'un équilibre entre les contraintes métier, les exigences de sécurité et les limites du projet.

L'architecture proposée applique les principes du Zero Trust, du moindre privilège et de la défense en profondeur tout en assurant la continuité des services existants.

Les risques résiduels ont été identifiés, documentés et accompagnés de recommandations d'évolution pour une seconde phase du projet.