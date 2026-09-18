# Nexus Financial - Final Security Audit Report

## 1. Objectif

Ce rapport simule l'audit final de l'infrastructure Nexus Financial après la mise en place des contrôles de sécurité.

Chaque contrôle contient :

1. **Verification Command** : commande utilisée pour vérifier le contrôle.
2. **Expected Output** : résultat attendu.
3. **Self-Assessment** : évaluation du contrôle.

---

# 2. SSH Hardening

## Verification Command

```bash
sshd -T | grep -E "permitrootlogin|passwordauthentication|pubkeyauthentication|maxauthtries"
```

## Expected Output

```text
permitrootlogin no
passwordauthentication no
pubkeyauthentication yes
maxauthtries 3
```

## Self-Assessment

**PASS**

L'accès SSH direct à `root` est désactivé. L'authentification par mot de passe est désactivée et les utilisateurs doivent utiliser des clés SSH individuelles.

---

# 3. Firewall - Default Deny

## Verification Command

```bash
ufw status verbose
```

## Expected Output

```text
Status: active
Default: deny (incoming), allow (outgoing)
```

## Self-Assessment

**PASS**

Le firewall UFW est actif et applique une politique **Default Deny** sur les connexions entrantes.

---

# 4. PostgreSQL Network Protection

## Verification Command

```bash
ufw status numbered | grep 5432
```

## Expected Output

```text
5432/tcp DENY IN Anywhere
5432/tcp ALLOW IN 10.0.1.10
```

## Self-Assessment

**PASS**

Le port PostgreSQL `5432` n'est plus accessible publiquement. Seul le serveur Web autorisé `10.0.1.10` peut accéder au service.

---

# 5. SSH Bastion Restriction

## Verification Command

```bash
ufw status numbered | grep 22
```

## Expected Output

```text
22/tcp ALLOW IN 10.0.1.20
```

## Self-Assessment

**PASS**

L'accès SSH aux serveurs est limité au Bastion Host `10.0.1.20`.

---

# 6. RBAC Groups

## Verification Command

```bash
getent group devs
getent group ops
getent group auditors
```

## Expected Output

```text
devs:x:...
ops:x:...
auditors:x:...
```

## Self-Assessment

**PASS**

Les groupes RBAC `devs`, `ops` et `auditors` sont présents.

Les permissions sont séparées selon les responsabilités des utilisateurs.

---

# 7. User Group Membership

## Verification Command

```bash
id sarah
id dave
id auditor
```

## Expected Output

```text
sarah: devs ops
dave: devs auditors
auditor: auditors
```

## Self-Assessment

**PASS**

Les utilisateurs sont associés aux groupes correspondant à leurs responsabilités.

---

# 8. Restricted Sudo Access

## Verification Command

```bash
cat /etc/sudoers.d/nexus-rbac
```

## Expected Output

```text
%ops ALL=(root) /bin/systemctl restart nginx
%ops ALL=(root) /bin/systemctl start nginx
%ops ALL=(root) /bin/systemctl stop nginx
%ops ALL=(root) /bin/systemctl status nginx
```

## Self-Assessment

**PASS**

Les membres du groupe `ops` disposent uniquement des commandes administratives nécessaires à la gestion de Nginx.

Aucun accès root complet n'est accordé par cette règle.

---

# 9. Sudoers Validation

## Verification Command

```bash
visudo -cf /etc/sudoers.d/nexus-rbac
```

## Expected Output

```text
/etc/sudoers.d/nexus-rbac: parsed OK
```

## Self-Assessment

**PASS**

La configuration sudo utilisée pour le RBAC est syntaxiquement valide.

---

# 10. Sensitive File Auditing

## Verification Command

```bash
auditctl -l
```

## Expected Output

Les règles doivent notamment contenir :

```text
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k sudo_changes
-w /etc/ssh/sshd_config -p wa -k ssh_changes
```

## Self-Assessment

**PASS**

Les modifications des fichiers critiques sont surveillées par `auditd`.

---

# 11. Privileged Command Monitoring

## Verification Command

```bash
auditctl -l | grep privileged_commands
```

## Expected Output

```text
-a always,exit -F arch=b64 -S execve -F euid=0 -F key=privileged_commands
```

Une règle équivalente peut également être présente pour `b32`.

## Self-Assessment

**PASS**

L'exécution de commandes avec les privilèges root est enregistrée afin de fournir une piste d'audit.

---

# 12. Audit Configuration Immutability

## Verification Command

```bash
auditctl -s | grep enabled
```

## Expected Output

```text
enabled 2
```

## Self-Assessment

**PASS**

La valeur `enabled 2` indique que la configuration d'audit est verrouillée et ne peut plus être modifiée avant un redémarrage.

---

# 13. Centralized Logging

## Verification Command

```bash
grep -R "10.0.1.30" /etc/rsyslog.d/
```

## Expected Output

```text
*.warning @@10.0.1.30:514
auth,authpriv.* @@10.0.1.30:514
kern.* @@10.0.1.30:514
```

## Self-Assessment

**PASS**

Les événements importants sont transmis au serveur central de logs `10.0.1.30`.

La centralisation réduit le risque qu'un attaquant puisse supprimer toutes les traces de son activité depuis un serveur compromis.

---

# 14. Rsyslog Service

## Verification Command

```bash
systemctl is-active rsyslog
```

## Expected Output

```text
active
```

## Self-Assessment

**PASS**

Le service de journalisation est actif.

---

# 15. Auditd Service

## Verification Command

```bash
systemctl is-active auditd
```

## Expected Output

```text
active
```

## Self-Assessment

**PASS**

Le service `auditd` est actif et collecte les événements de sécurité.

---

# 16. Fail2ban Protection

## Verification Command

```bash
systemctl is-active fail2ban
fail2ban-client status sshd
```

## Expected Output

```text
active
Status for the jail: sshd
```

## Self-Assessment

**PASS**

Fail2ban protège le service SSH contre les tentatives répétées d'authentification.

---

# 17. Kernel Network Hardening

## Verification Command

```bash
sysctl net.ipv4.ip_forward
sysctl net.ipv4.conf.all.accept_redirects
sysctl net.ipv4.conf.all.accept_source_route
sysctl net.ipv4.tcp_syncookies
```

## Expected Output

```text
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
```

## Self-Assessment

**PASS**

Les paramètres réseau du noyau ont été renforcés afin de réduire plusieurs risques réseau.

---

# 18. Shared SSH Key Revocation

## Verification Command

```bash
find /home /root -name "nexus_master.pem" -type f 2>/dev/null
```

## Expected Output

```text
No output
```

## Self-Assessment

**PASS**

La clé SSH partagée `nexus_master.pem` ne doit plus être utilisable.

Les administrateurs doivent utiliser des clés SSH individuelles.

---

# 19. Nginx Configuration Permissions

## Verification Command

```bash
ls -ld /etc/nginx
find /etc/nginx -type f -maxdepth 2 -ls | head
```

## Expected Output

Les fichiers de configuration doivent appartenir à `root` et ne doivent pas être modifiables par les utilisateurs non autorisés.

Exemple :

```text
root root
-rw-r--r--
```

## Self-Assessment

**PASS**

Les développeurs ne disposent pas d'un accès d'écriture direct aux fichiers de configuration Nginx.

---

# 20. Log Permissions

## Verification Command

```bash
ls -ld /var/log/nginx
ls -l /var/log/nginx
```

## Expected Output

```text
root auditors
drwxr-x---
```

Les fichiers de logs doivent utiliser des permissions restrictives telles que :

```text
-rw-r-----
```

## Self-Assessment

**PASS**

Les logs Nginx sont protégés contre les modifications non autorisées et sont accessibles au groupe d'audit prévu.

---

# 21. Incident Response Plan

## Verification Command

```bash
grep -Ei "Identification|Containment|Eradication|Recovery|Lessons Learned|Escalade" policy/incident_response_plan.md
```

## Expected Output

```text
Identification
Containment
Eradication
Recovery
Lessons Learned
Escalade
```

## Self-Assessment

**PASS**

Un playbook de réponse à une compromission de base de données est documenté.

Il définit l'identification, l'escalade, le confinement, l'éradication, la récupération et le retour d'expérience.

---

# 22. Physical Security Plan

## Verification Command

```bash
test -s policy/physical_security_plan.md && echo "Physical security plan present"
```

## Expected Output

```text
Physical security plan present
```

## Self-Assessment

**PASS**

Les risques physiques identifiés lors de l'évaluation initiale sont documentés avec des mesures immédiates, court terme et long terme.

---

# 23. Threat Model

## Verification Command

```bash
grep -Ei "STRIDE|Spoofing|Tampering|Repudiation|Information Disclosure|Denial of Service|Elevation of Privilege" policy/threat_model.md
```

## Expected Output

Le rapport doit contenir les catégories STRIDE :

```text
Spoofing
Tampering
Repudiation
Information Disclosure
Denial of Service
Elevation of Privilege
```

## Self-Assessment

**PASS**

Un Threat Model basé sur STRIDE permet d'identifier les principales menaces techniques, humaines et physiques de Nexus Financial.

---

# 24. Access Control Policy

## Verification Command

```bash
test -s policy/access_control_policy.md && echo "Access control policy present"
```

## Expected Output

```text
Access control policy present
```

## Self-Assessment

**PASS**

Une politique de contrôle d'accès documente l'authentification, le RBAC, le principe du moindre privilège, SSH et les restrictions réseau.

---

# 25. Final Self-Assessment

## Verification Command

```bash
ufw status
systemctl is-active rsyslog
systemctl is-active auditd
systemctl is-active fail2ban
auditctl -s
sshd -T | grep -E "permitrootlogin|passwordauthentication"
```

## Expected Output

Les contrôles principaux doivent retourner :

```text
UFW: active
rsyslog: active
auditd: active
fail2ban: active
auditd enabled: 2
permitrootlogin no
passwordauthentication no
```

## Self-Assessment

**PASS - Controls implemented and verifiable**

Les principales faiblesses découvertes au début de l'audit ont été traitées par une combinaison de contrôles :

* **Governance** : politiques de sécurité et procédure de réponse aux incidents ;
* **Prevention** : SSH hardening, firewall, RBAC, moindre privilège et restrictions PostgreSQL ;
* **Detection** : auditd, rsyslog centralisé et Fail2ban ;
* **Response** : playbook de réponse à une compromission de base de données ;
* **Physical Security** : contrôle des visiteurs, salle serveur, badges et verrouillage des postes.

## Risques résiduels

Certains contrôles nécessitent encore une validation opérationnelle :

* tester réellement les sauvegardes S3 ;
* vérifier régulièrement les restaurations ;
* déployer un VPN fiable pour les équipes distantes ;
* mettre en place une gestion centralisée des secrets ;
* vérifier périodiquement les règles firewall ;
* tester le plan de réponse aux incidents ;
* réaliser des revues régulières des droits utilisateurs ;
* poursuivre la sensibilisation des employés.

L'environnement est désormais plus contrôlé, surveillé et auditable, mais les contrôles doivent être testés et maintenus régulièrement pour rester efficaces.
