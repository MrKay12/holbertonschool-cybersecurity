Identity & Access Management

Explication des commandes utilisees par exercice (sans prendre en compte les flags).

Exercice 0 - audit_uid
- awk: extrait et filtre des champs dans un fichier texte structure.

Exercice 1 - audit_shells
- awk: commande deja expliquee dans l'exercice 0.

Exercice 2 - audit_groups
- awk: commande deja expliquee dans l'exercice 0.
- id: affiche les informations d'un utilisateur et ses groupes.
- tr: remplace ou transforme des caracteres.
- grep: filtre les lignes selon un motif.
- sed: edite et transforme du texte en flux.

Exercice 3 - harden_ssh
- sed: edite et transforme du texte en flux.
- grep: filtre les lignes selon un motif.
- echo: affiche du texte.
- sshd: valide/execute la configuration du serveur SSH.
- systemctl: pilote les services systeme.

Exercice 4 - pw_policy
- dpkg: interroge ou gere des paquets Debian.
- apt-get: installe/met a jour des paquets.
- grep: commande deja expliquee dans l'exercice 2.
- sed: commande deja expliquee dans l'exercice 2.
- echo: commande deja expliquee dans l'exercice 3.

Exercice 5 - audit_crypto
- awk: commande deja expliquee dans l'exercice 0.

Exercice 6 - onboard
- useradd: cree un nouvel utilisateur.
- passwd: gere le mot de passe d'un utilisateur.
- mkdir: cree un repertoire.
- echo: commande deja expliquee dans l'exercice 3.
- chmod: change les permissions d'un fichier ou dossier.
- chown: change le proprietaire et/ou le groupe.

Exercice 7 - sudo_config
- echo: commande deja expliquee dans l'exercice 3.
- chmod: commande deja expliquee dans l'exercice 6.
- visudo: verifie/edite la configuration sudo de facon securisee.