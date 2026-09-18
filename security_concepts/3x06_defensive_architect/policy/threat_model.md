Nexus Financial - Modèle de Menaces STRIDE
1. Objectif

Ce modèle de menaces identifie les principaux risques de sécurité de Nexus Financial concernant les systèmes informatiques, les employés, les données et les locaux.

L'analyse utilise la méthode STRIDE :

S - Spoofing (Usurpation) : se faire passer pour un utilisateur légitime.
T - Tampering (Altération) : modifier des données ou systèmes sans autorisation.
R - Repudiation (Répudiation) : effectuer une action sans pouvoir identifier son auteur.
I - Information Disclosure (Divulgation) : exposer des informations sensibles.
D - Denial of Service (Déni de service) : rendre un service indisponible.
E - Elevation of Privilege (Élévation de privilèges) : obtenir plus de droits que prévu.
2. Analyse STRIDE
Composant	STRIDE	Menace principale	Acteur probable
Accès au bâtiment	Usurpation	Une personne non autorisée peut entrer facilement car il n'y a pas de réceptionniste et le système visiteurs est hors service.	Visiteur / Ingénieur social
Salle serveur "The Core"	Altération	La porte ouverte permet de débrancher, modifier, voler ou connecter du matériel aux serveurs.	Visiteur / Employé malveillant
Switchs réseau	Élévation de privilèges	Les ports réseau inutilisés mais actifs permettent de connecter un appareil non autorisé au réseau interne.	Visiteur / Attaquant avec accès physique
Tableau blanc	Divulgation d'informations	Les mots de passe Wi-Fi et de la base de staging sont visibles par toute personne présente dans les locaux.	Visiteur / Prestataire
MacBooks des employés	Usurpation	Les ordinateurs laissés déverrouillés permettent d'utiliser directement la session d'un employé.	Employé malveillant / Visiteur
Badges d'accès	Usurpation	Les badges génériques et badges de secours permettent d'entrer sans identifier précisément la personne.	Employé / Visiteur
Accès SSH Production	Élévation de privilèges	La clé nexus_master.pem partagée donne à plusieurs personnes un accès privilégié à la production.	Compte développeur compromis / Employé malveillant
Slack #dev-ops	Divulgation d'informations	La clé SSH privée de production peut être récupérée si un compte Slack est compromis.	Attaquant externe
Base PostgreSQL	Divulgation d'informations	Le port 5432 ouvert à 0.0.0.0/0 expose directement la base de données à Internet.	Attaquant externe
Sauvegardes BDD	Déni de service	Les sauvegardes ne sont ni vérifiées ni surveillées, ce qui peut empêcher une restauration après un incident.	Ransomware / Erreur humaine
Bucket S3	Divulgation d'informations	Les dumps de la base peuvent être exposés si les permissions du bucket sont incorrectes.	Attaquant externe
Serveurs de production	Altération	Les développeurs ayant accès root peuvent modifier ou supprimer accidentellement ou volontairement des données critiques.	Développeur / Employé malveillant
Journalisation	Répudiation	L'absence de logs empêche de déterminer qui a effectué une action ou provoqué un incident.	Employé malveillant / Compte compromis
Plateforme Web	Déni de service	Sans logs ni surveillance, une panne ou une attaque peut être difficile à détecter et diagnostiquer.	Attaquant externe / Défaillance logicielle
Panel administrateur	Usurpation	Le PIN faible du CEO (1975) peut être facilement deviné et permettre l'accès au compte administrateur.	Attaquant externe
Comptes privilégiés	Élévation de privilèges	Les privilèges root excessifs permettent à un compte développeur compromis de contrôler toute la production.	Attaquant externe avec compte compromis
Employés	Divulgation d'informations	Les mots de passe visibles, secrets partagés et postes déverrouillés peuvent exposer des informations sensibles.	Ingénieur social / Employé malveillant
3. Risques prioritaires

Les risques les plus urgents sont :

Base PostgreSQL exposée à Internet
Le port 5432 doit être immédiatement limité aux réseaux autorisés ou accessible uniquement via VPN.
Clé SSH de production partagée
La clé nexus_master.pem doit être révoquée et remplacée par des clés SSH individuelles.
Accès root généralisé
Les développeurs doivent uniquement disposer des permissions nécessaires à leur travail selon le principe du moindre privilège.
Absence de journalisation centralisée
Les logs doivent être centralisés afin de détecter et analyser les incidents.
Accès physique aux serveurs
La salle "The Core" doit être verrouillée et accessible uniquement aux personnes autorisées.
Mauvaise gestion des identifiants
Les mots de passe, PIN et clés SSH doivent être retirés des tableaux blancs et de Slack et stockés de manière sécurisée.
Sauvegardes non vérifiées
Les sauvegardes doivent être surveillées et des tests de restauration doivent être réalisés régulièrement.
4. Acteurs de menace
Attaquant externe

Peut exploiter la base PostgreSQL exposée, les mots de passe faibles, les services Internet ou des comptes compromis.

Employé malveillant

Un employé disposant de privilèges excessifs peut voler, modifier ou supprimer des données.

Compte employé compromis

Un attaquant ayant compromis un compte peut accéder à Slack, récupérer des clés SSH et atteindre les serveurs de production.

Visiteur / Ingénieur social

Une personne peut entrer dans les locaux, consulter les mots de passe visibles, utiliser un ordinateur déverrouillé ou accéder physiquement aux serveurs.

Employé faisant une erreur

Un utilisateur légitime disposant de droits excessifs peut accidentellement supprimer ou modifier des données critiques.

5. Conclusion

Nexus Financial ne dispose actuellement pas d'une véritable défense en profondeur.

Plusieurs vulnérabilités peuvent être combinées, par exemple :

Visiteur non autorisé → entrée dans les locaux → récupération des identifiants sur le tableau blanc → connexion sur un port réseau actif → accès au réseau interne.

Un autre scénario possible :

Compte développeur compromis → accès à Slack → récupération de nexus_master.pem → connexion à la production → accès privilégié → vol ou modification des données.

Les priorités sont donc : contrôle des accès physiques, sécurisation des identifiants, restriction réseau, moindre privilège, journalisation centralisée et sauvegardes vérifiées.