# ApexVault - Security Design Document

## Executive Summary

ApexVault est un système de stockage sécurisé destiné aux clients VIP d'ApexFin.

La sécurité repose sur trois principes :
- Authentification forte sans mot de passe.
- Chiffrement empêchant même les administrateurs de lire les fichiers clients.
- Journalisation externe et non modifiable.

## 1. Authentication Strategy

### Selected Technology

**FIDO2 avec clé de sécurité matérielle.**

Les utilisateurs s'authentifient avec une clé physique FIDO2 et une vérification locale par PIN ou biométrie.

### Justification

FIDO2 utilise la cryptographie asymétrique : la clé privée reste sur le périphérique de l'utilisateur et aucun mot de passe n'est transmis au serveur.

Cela protège mieux contre le phishing et le vol d'identifiants que les mots de passe ou les codes SMS.

## 2. Authorization Model

### Model Selected

**RBAC (Role-Based Access Control).**

Chaque utilisateur possède un rôle avec uniquement les permissions nécessaires :
- Client : accès uniquement à ses propres fichiers.
- Administrateur : gestion du serveur.
- Auditeur : accès aux journaux de sécurité.

### Admin Restriction

Les fichiers sont chiffrés **côté client avant leur envoi au serveur**.

Les clés de déchiffrement restent chez le client et ne sont jamais stockées sur le serveur.

Ainsi, même un administrateur `root` peut gérer, copier ou supprimer les fichiers chiffrés, mais il ne peut pas lire leur contenu.

## 3. Accounting Architecture

### Storage Location

Les logs sont envoyés en temps réel vers un **serveur de logs centralisé et séparé** du serveur ApexVault.

Un attaquant qui compromet ApexVault ne peut donc pas simplement supprimer les traces de son attaque.

### Integrity Mechanism

Les logs utilisent un stockage **append-only / WORM (Write Once, Read Many)**.

Les nouvelles entrées peuvent être ajoutées, mais les anciennes ne peuvent pas être modifiées ou supprimées.

Cela garantit l'intégrité des journaux et permet de conserver des preuves fiables après un incident.