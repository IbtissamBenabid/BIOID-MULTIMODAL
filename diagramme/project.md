# BioID - Documentation technique complète

Ce document décrit en détail l'architecture, les fichiers et modules du projet BIOID-MULTIMODAL. Il explique le rôle de chaque fichier, les technologies et outils utilisés, le flux applicatif (enrôlement, vérification, identification), les méthodes d'évaluation biométrique (FAR, FRR, EER) et les aspects sécurité, audit et conformité.

---

## Table des matières

1. Vue d'ensemble
2. Arborescence et description des fichiers
3. Modules détaillés (par fichier dans `modules/`)
4. Flux de l'application (enrôlement, vérification, identification)
5. Métriques biométriques (FAR, FRR, EER) - méthodes et implémentation
6. Sécurité (chiffrement, token, gestion des clés)
7. Audit (journalisation, format, ingestion pour métriques)
8. Conformité (RGPD / Loi 09-08)
9. Déploiement (Docker, docker-compose, Nginx)
10. Commandes utiles et tests rapides
11. Annexes & recommandations

---

## 1) Vue d'ensemble

BIOID est une application Flask (Python) fournissant un système d'identification biométrique multimodal (visage, empreinte digitale, voix). Le projet est conçu pour un usage académique / prototype conforme aux principes de confidentialité et sécurité. Les données peuvent être stockées localement (JSON dans `data/database`) ou dans PostgreSQL (production) selon la configuration.

Principales responsabilités :
- Capture faciale en temps réel via webcam
- Traitement d'empreintes digitales (upload) et extraction de minutiae
- Traitement vocal (optionnel) et extraction MFCC
- Génération d'ID biométriques, vérification 1:1 et identification 1:N
- Authentification RBAC, chiffrement des descripteurs biométriques
- Journalisation d'audit et métriques biométriques (FAR/FRR/EER, bias analysis)
- Composants de conformité (consentement, rétention, PIA)

---

## 2) Arborescence et description des fichiers

Fichiers de haut niveau :

- `app.py` : point d'entrée principal. Définit l'application Flask, routes API (auth, capture, enrollment, verify, identify, metrics, audit, compliance), middleware d'authentification (JWT via RBAC), initialisation des modules (BioIDGenerator, SecurityManager, AuditLogger, RBACManager, BiometricMetrics, ComplianceManager, RiskAssessment, UseCaseRepository), streaming vidéo et pages templates.

- `config.py` : configuration globale (dossiers data, chemins, paramètres de capture, DATABASE_URL pour PostgreSQL, paramètres JWT).

- `Dockerfile` : image de production (python:3.11-slim), installation des dépendences système (OpenCV, ffmpeg, audio libs), pip install requirements et gunicorn pour déploiement.

- `docker-compose.yml` : composition des services (bioid container, optionnel nginx proxy). Définit volumes persistants (`bioid-data`, `bioid-logs`) et variables d'environnement.

- `requirements.txt` : dépendances Python (face_recognition, dlib, Flask, cryptography, librosa, etc.).

- `templates/` : pages HTML (login, index, enroll, verify, metrics).

- `data/` : arborescence de stockage local (faces/, fingerprints/, database/, audit/, metrics/, keys/, compliance/).

- `modules/` : dossier contenant les composants applicatifs (détaillé ci-dessous).

- `project.md` : ce fichier de documentation.

---

## 3) Modules détaillés (fichiers de `modules/`)

Pour chaque module, sa description, responsabilités, méthodes publiques importantes.

### `modules/bioid_generator.py`
- Rôle : gérer l'enregistrement et la recherche des bénéficiaires, générer l'ID biométrique (UUID) et le hash biométrique.
- Fonctions clés :
  - `register_beneficiary(name, face_encoding, fingerprint_features, metadata)` : enregistre un bénéficiaire et sauvegarde dans le JSON (`data/database/beneficiaries.json`).
  - `generate_uuid(...)` : génère un identifiant unique `BIO-XXXXXXXX-XXXX` (UUID v4 formaté).
  - `generate_biometric_hash(face_encoding, fingerprint_features)` : hash SHA-256 des vecteurs combinés.
  - `find_by_biometrics(face_encoding, fingerprint_features)` : recherche 1:N dans la DB (distance euclidienne pour visage, similarité cosinus pour empreintes).
  - `verify_identity(bio_id, ...)` : vérification 1:1 multi-modale (face, fingerprint, voice) et calcul de confiance.
- Notes : stocke des vecteurs en clair dans JSON; en production on recommande de stocker chiffré ou seulement des templates chiffrés.


### `modules/security.py`
- Rôle : chiffrement des descripteurs (Fernet), génération et validation de tokens non-JWT (méthodes utilitaires), hashing biométrique, pseudonymisation.
- Fonctions clés :
  - `encrypt_descriptor(descriptor)` / `decrypt_descriptor(encrypted)` : chiffrer/déchiffrer descripteurs (Fernet dérivé d'une clé maître).
  - `hash_biometric(data)` : SHA-256 pour comparaison non réversible.
  - `generate_token(bio_id, expiry_hours)` / `verify_token(token)` : token HMAC simple (utilisé pour cas d'usage interne).
  - `get_consent_template()` / `validate_consent(consent_data)` (via `DataProtection`).
- Stocke la `master.key` dans `data/keys/master.key` (actuellement, fichier local).


### `modules/audit.py`
- Rôle : journalisation structurée des événements (enrôlement, vérification, identification, audit access, security alert, consent).
- Format : fichiers JSON journaliers `data/audit/audit_YYYY-MM-DD.json`. Chaque événement contient : event_id, timestamp, event_type, actor, bio_id, success, ip_address, details.
- Fonctions clés :
  - `log_event(event_type, actor, bio_id, details, success, ip_address)`
  - `log_enrollment(...)`, `log_verification(...)`, `log_identification(...)`, `log_data_access(...)`, etc.
  - `get_logs(start_date, end_date, event_type, bio_id)` : lecture et filtrage des logs.
  - `get_statistics(days)` : agrégation simple (par type, taux de succès, unique bio_ids, security_alerts).
- Rôle essentiel : source de vérité pour l'ingestion des métriques biométriques (BiometricMetrics ingère `data/audit` pour générer `verification_results.json`).


### `modules/rbac.py`
- Rôle : gestion des rôles et permissions, intégration avec `DatabaseManager` pour l'authentification et génération de tokens JWT.
- Principaux éléments :
  - Enum `Role`, `Permission`, matrice `ROLE_PERMISSIONS`.
  - `RBACManager` : méthodes d'authentification (`authenticate_user`), création et vérification de tokens via `DatabaseManager` (JWT), création d'utilisateurs, récupération des permissions.
  - Décorateur `require_permission(permission)` pour les routes Flask.


### `modules/database.py`
- Rôle : abstraction d'accès aux données relationnelles (PostgreSQL) et gestion des utilisateurs/tokens.
- Comportement :
  - par défaut, crée des tables `users`, `beneficiaries`, `audit_log` si PostgreSQL est utilisé (DATABASE_URL configuré).
  - méthodes : `get_connection()`, `authenticate_user()`, `create_user()`, `create_access_token()`, `create_refresh_token()`, `verify_token()`, `store_refresh_token()`, `get_user_by_refresh_token()`, `update_last_login()`, `log_audit_event()`.
- Notes : permet basculer du stockage JSON vers PostgreSQL en production.


### `modules/face_capture.py`
- Rôle : capture vidéo via OpenCV, détection de visages et extraction d'encodages via `face_recognition`.
- Fonctions : `start_capture(camera_index)`, `get_average_encoding()`, `save_captures(save_dir, beneficiary_id)`, et utilitaire `compare_faces(known_encoding, unknown_encoding, tolerance)`.
- Utilisé par `app.py` pour le streaming `/api/video_feed` et la capture via l'interface d'enrôlement.


### `modules/fingerprint_processor.py`
- Rôle : traitement des images d'empreintes digitales (prétraitement, skeletonisation, extraction de minutiae, vecteur de caractéristiques).
- Principales étapes :
  - `load_from_bytes(image_bytes)` / `load_image(filepath)`
  - `preprocess()` : resize, normalisation, CLAHE, blur, binarisation adaptative, opérations morphologiques
  - `extract_minutiae()` : squelettisation, détection terminaisons et bifurcations, filtrage des bords
  - `extract_features()` : vecteur combinant nombres de minutiae, positions moyennes, histogramme d'orientation, distances, etc., normalisé
  - `compare_fingerprints(features1, features2, threshold)` : similarité cosinus et comparaison
- Remarque : dépendances `scikit-image`, `Pillow`, `opencv-python`.


### `modules/voice_processor.py` (optionnel)
- Rôle : traitement audio, extraction MFCCs, features vocales.
- Fonctions : `record_voice()`, `load_audio(filepath)`, `load_from_bytes(audio_bytes)`, `preprocess()`, `extract_features()`, `save_audio(save_dir, beneficiary_id)`, `compare_voices(features1, features2)`.
- Dépendances optionnelles : `librosa`, `sounddevice`, `scipy`.


### `modules/metrics.py`
- Rôle : calcul et analyse des métriques biométriques (FAR, FRR, EER), ingestion depuis `data/audit`, génération de rapports et analyses de biais.
- Méthodes principales :
  - `_ingest_from_audit_logs()` : lit `data/audit/*.json` et convertit les events `verification` en enregistrements `genuine`/`impostor` (score normalisé 0..1, lower=meilleur)
  - `record_verification(is_genuine, score, modality)` : ajoute un enregistrement et sauvegarde `verification_results.json`
  - `calculate_far_frr(threshold, modality)` : calcule FAR et FRR pour un seuil
  - `calculate_eer(modality)` : calcule EER (via balayage de seuils et recherche du point FAR ~ FRR)
  - `analyze_thresholds(modality)`, `generate_report()`, `generate_bias_report(demographic_data)`

---

## 4) Flux de l'application

Résumé des scénarios principaux :

A) Enrôlement (Enroll)
1. Utilisateur (operator/admin) s'authentifie via `/api/auth/login` (RBAC). JWT renvoyé.
2. Frontend capture le visage via `/api/video_feed` (stream) ou demande capture via `/api/capture_face` en envoyant l'image encodée.
3. Operateur Uploade une image d'empreinte via `/api/process_fingerprint` (multipart).
4. Optionnel : enregistre un fichier audio via `/api/process_voice`.
5. Frontend envoie POST `/api/register` avec `name`, `face_encoding`, `fingerprint_features`, `voice_features`, `consent`.
6. `bioid_generator.register_beneficiary()` génère `bio_id`, `bio_hash` et stocke le profil (JSON ou PG). AuditLogger log l'enrôlement. SecurityManager peut chiffrer les templates.

B) Vérification 1:1 (Verify)
1. Authentifié, opérateur envoie POST `/api/verify` avec `bio_id` et features capturées.
2. `BioIDGenerator.verify_identity()` compare les features fournies avec le profil stocké (face/fp/voice), retourne `verified`, distances et confidences.
3. AuditLogger log l'événement; Metrics enregistre le score (genuine/impostor si `record_metrics` activé).

C) Identification 1:N (Identify)
1. Authentifié, frontend envoie POST `/api/identify` avec features (face_encoding ou fingerprint_features).
2. `BioIDGenerator.find_by_biometrics()` parcourt la base et renvoie le meilleur match (utilise distance euclidienne pour face, similarité cosinus pour fingerprint).
3. AuditLogger log l'identification (query hash).

D) Audit & Reporting
- AuditLogger écrit des événements JSON par jour. BiometricMetrics ingère ces logs pour construire `verification_results.json`, calcule FAR/FRR/EER, génère rapports et analyse des biais.

---

## 5) Métriques biométriques (FAR, FRR, EER) — méthodes et implémentation

Termes :
- Score : valeur numérique issue d'une comparaison (dans ce projet, on convertit la confiance en un "score" où plus bas = meilleur match (distance-like)).
- genuine : tentatives légitimes (vrai positif attendu)
- impostor : tentatives imposteurs (faux positif attendu)

Définitions :
- FAR (False Acceptance Rate) : proportion d'essais imposteurs acceptés (faussement acceptés) pour un seuil donné.
- FRR (False Rejection Rate) : proportion d'essais légitimes rejetés (faussement rejetés) pour un seuil donné.
- EER (Equal Error Rate) : point où FAR = FRR (souvent exprimé en %), utilisé pour caractériser la dissociation performance/erreur d'un système.

Implémentation dans `modules/metrics.py` :
- Ingestion : convertir les `confidence` (ex: pour face 0..100) en score normalisé 0..1 via heuristique : si confiance > 1 => normaliser /100 puis score = 1 - normalized. L'idée: score bas = meilleur.
- Pour un seuil t :
  - FAR(t) = (# impostor scores <= t) / total_impostor
  - FRR(t) = (# genuine scores > t) / total_genuine
  - Les valeurs sont retournées en pourcentage (multiplées par 100).
- EER : balayage de seuils (linspace entre min et max des scores) et recherche du seuil où |FAR - FRR| est minimal ; retourne EER = (FAR+FRR)/2 au seuil optimal.

Pourquoi cette méthode ?
- Facile à implémenter et robuste pour petits prototypes.
- Interprétation directe avec les scores enregistrés (issues des logs d'audit).
- Pour production, recommander d'utiliser des bibliothèques spécialisées (sklearn ROC/AUC, ou outils statistiques plus avancés) et d'effectuer interpolation fine/AUC.

Limitations et notes :
- Le projet convertit la notion de "confiance" (pourcentage) en "score distance" ; il faut s'assurer que tous les modules renvoient des valeurs comparables.
- EER estimation par grille peut être approximative ; interpolation ou méthodes analytiques sont recommandées si besoin.

---

## 6) Sécurité (détail)

Principes et éléments :

A) Chiffrement des descripteurs
- `SecurityManager` dérive une clé Fernet (256-bit) à partir d'une `master.key` stockée dans `data/keys/master.key`.
- Méthode : PBKDF2HMAC (SHA256, salt `bioid_salt_v1`, iterations=100000) -> clé Fernet.
- `encrypt_descriptor` convertit le descripteur (liste ou numpy array) en JSON bytes puis chiffre via Fernet. Valeur stockée base64.
- `decrypt_descriptor` récupère le descripteur en clair pour comparaisons si nécessaire.

Recommandation : utiliser un Key Vault (Azure KeyVault, HashiCorp Vault) en production plutôt que fichier local.

B) Authentication & RBAC
- Authentification : JWT (via `DatabaseManager.create_access_token`, secret `JWT_SECRET_KEY` dans `config.py`) avec expiry (access minutes, refresh days).
- `RBACManager` applique les permissions (Role: 'admin' ou 'agent') et expose `require_permission` pour sécuriser les routes.
- Refresh token stocké dans la base `users.refresh_token` et invalidé lors de logout.

C) Intégrité et hashing
- `hash_biometric` (SHA-256) : permet détection de doublons sans stocker les données brutes (pseudonymisation / comparaison non réversible).

D) Transport & stockage
- Transport : recommander HTTPS via Nginx reverse proxy (docker-compose profile `with-nginx`) — TLS côté client.
- Stockage : les descripteurs doivent être chiffrés avant persistance; les fichiers `data/audit` et `data/database` accessibles à l'hôte — prévoir permissions et backups chiffrés.

E) Bonnes pratiques supplémentaires
- Rotation des clés et protections d'accès (Key Vault).
- Limiter le stockage des descripteurs en clair ; conserver uniquement des templates chiffrés ou des hash.
- Audit d'accès aux clés et usage des tokens.

---

## 7) Audit (détail)

Format et stockage
- Fichiers JSON journaliers : `data/audit/audit_YYYY-MM-DD.json`.
- Chaque entrée contient : `event_id`, `timestamp`, `event_type`, `actor`, `bio_id`, `success`, `ip_address`, `details`.
- Types d'événements : enrollment, authentication, identification, verification, data_access, data_modification, consent_given, consent_withdrawn, security_alert, login, logout, failed_authentication.

Raisons et utilité
- Traçabilité (qui a fait quoi, quand, depuis quelle IP).
- Preuve de conformité pour RGPD/Loi 09-08.
- Source pour métriques biométriques (BiometricMetrics ingère ces logs pour analyser performance et biais).

Ingestion et métriques
- `BiometricMetrics._ingest_from_audit_logs()` lit tous les fichiers JSON dans `data/audit` et extrait les événements de type `verification`.
- Transforme `confidence` (dictionnaire) en score compris entre 0 et 1 (lower = meilleur) selon heuristique, puis alimente `genuine` ou `impostor`.

Accessibilité
- API expose `GET /api/audit/logs` et `GET /api/audit/stats` (protégees par RBAC) pour consultation et export.

Sécurité des logs
- Logs contiennent des identifiants biométriques (bio_id) : appliquer contrôle d'accès strict, anonymisation pour export, rétention selon politique.

---

## 8) Conformité (RGPD / Loi 09-08)

Composants réalisés :
- Enregistrement du consentement : `ComplianceManager.record_consent(bio_id, consent_data)` écrit `data/compliance/consents.json`.
- Retrait du consentement : `withdraw_consent(bio_id)` marque le consentement comme retiré et logue l'événement.
- Politique de rétention : fichiers `data/compliance/retention_policies.json` détaillent la durée de rétention par type de données.
- Privacy Impact Assessment (PIA) : `ComplianceManager.get_privacy_impact_assessment()` génère un rapport (template).

Exigences pratiques :
- Consentement explicite avant enrôlement (vérifier `consent_given` avant `register_beneficiary`).
- Droit à l'effacement : API `/api/beneficiaries/<bio_id>` DELETE implémente la suppression et log d'audit.
- Pseudonymisation : `SecurityManager.pseudonymize_id(original_id)` pour export/anonymisation.
- Documentation & preuve : conserver logs d'accès et d'opérations, export possible pour audits.

Remarques légales
- Ce projet est un prototype académique; une revue légale dédiée est requise pour un usage réel (notamment pour la Loi 09-08 et traitements sensibles).

---

## 9) Déploiement

Local (développement) :
- Créer un environnement virtuel et installer les dépendances listées dans `requirements.txt`.
- Lancer `python app.py` (le serveur écoute `0.0.0.0:5000` en debug dans l'implémentation actuelle).

Production (Docker) :
- `docker build -t bioid-app .`
- `docker-compose up -d` (profile `with-nginx` pour activer nginx)
- Gunicorn est configuré dans `Dockerfile` comme process manager.

Volumes :
- `bioid-data` (stocke `data/`) est monté dans le conteneur pour persistance.
- `bioid-logs` pour logs d'application.

Sécurité :
- Nginx sert de reverse-proxy, gérer TLS et redirections, config dans `nginx.conf`.
- Remplacer la `master.key` par un secret manager en production.

---

## 10) Commandes utiles & tests rapides

Activer venv (Linux/macOS):

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Docker (build & run):

```bash
docker build -t bioid-app .
docker-compose up -d --build
```

Générer diagramme PlantUML (si `plantuml.jar` installé) :

```bash
# supposer que vous avez un fichier architecture.puml
java -jar plantuml.jar architecture.puml
```

Tests unitaires (si fournis) :
- `test_metrics_fix.py` existe dans la racine. Utiliser pytest si approprié.

---

## 11) Annexes & recommandations

- Remplacer `master.key` fichier local par un Key Vault (Azure, AWS KMS, HashiCorp Vault).
- Migrer progressivement `data/database/beneficiaries.json` vers PostgreSQL et chiffrer les descripteurs avant stockage.
- Externaliser les composants lourds (traitement fingerprint/voice) dans des workers séparés si montée en charge.
- Mettre en place monitoring (Prometheus/Grafana), CI/CD et tests d'intégration.
- Compléter la documentation légale (registre des traitements), revue d'impact et politique de breach response.

---

Si tu veux, je peux :
- Ajouter un fichier `ARCHITECTURE.puml` généré à partir du diagramme PlantUML que j'ai préparé précédemment.
- Ajouter une rubrique "Quick start" réduite dans `project.md` (installation minimale) ou un `README.md` principal.
- Générer une version PDF/PNG du diagramme.

---

## 12) Stockage technique des données biométriques

Où et comment les données biométriques sont stockées actuellement :

- Stockage local (prototype) : fichiers JSON dans `data/database/beneficiaries.json`. Chaque enregistrement contient :
  - `bio_id` (ex: BIO-XXXXXXXX-XXXX)
  - `name`, `registration_date`, `status`
  - `bio_hash` (SHA-256 du/descripteur combiné)
  - `face_encoding` : vecteur 128D (liste de floats) produit par `face_recognition`
  - `fingerprint_features` : vecteur flottant (résultat de `FingerprintProcessor.extract_features()`)
  - `metadata` : peut contenir `voice_features` (vecteur MFCC), consentement, opérateur, etc.

- Stockage production (optionnel) : PostgreSQL (table `beneficiaries`) via `modules/database.py`. Colonnes prévues : `bio_id`, `name`, `bio_hash`, `face_encoding` (TEXT), `fingerprint_features` (TEXT), `voice_features` (TEXT), `metadata` (JSONB).

Recommandation de sécurité pour le stockage :
- Ne pas conserver les vecteurs biométriques en clair en production. Utiliser `SecurityManager.encrypt_descriptor()` pour chiffrer les vecteurs avant de les écrire dans la base ou le JSON. Stocker la clé maître dans un Key Vault (Azure Key Vault, AWS KMS, HashiCorp Vault) et non en fichier local.
- Conserver `bio_hash` (SHA-256) pour détection de doublons / pseudonymisation (hash irréversible), utile pour recherche de doublons sans exposer les templates.

Format et sérialisation :
- Les vecteurs sont sérialisés en JSON (listes) puis éventuellement chiffrés et encodés en base64 pour stockage. Pour PostgreSQL, utiliser `JSONB` ou `TEXT` pour les blobs chiffrés.

---

## 13) Enregistrement (enrôlement) - détail technique étape par étape

1. Capture faciale
   - Le frontend démarre le flux `/api/video_feed` ou envoie une image via `/api/capture_face`.
   - La pipeline : capture image -> conversion BGR->RGB -> détection de visage -> extraction d'un encodage 128D via `face_recognition.face_encodings()`.
   - Pratique : prendre N captures (ex : 10 ou 20) et calculer l'encodage moyen (`np.mean`) pour améliorer la robustesse.
   - Landmarks : le projet utilise actuellement l'encodage 128D. Les landmarks (points de repère faciaux) peuvent être extraits via `face_recognition.face_landmarks()` ou `dlib` si nécessité (ex : alignement, liveness). Actuellement, les landmarks ne sont pas stockés par défaut, mais on peut :
     - stocker un résumé (ex: distances relative nose-eye) ou
     - stocker les landmarks chiffrés si besoin d'audit/visualisation.

2. Capture d'empreinte digitale
   - Upload d'image via `/api/process_fingerprint`.
   - Pipeline : lecture -> redimensionnement/normalisation -> CLAHE -> binarisation adaptative -> opérations morphologiques -> squelettisation -> extraction des minutiae (terminaisons, bifurcations).
   - Construction d'un vecteur de caractéristiques (features) : counts, positions moyennes, angles, histogramme d'orientation, distances entre minutiae, normalisé.

3. Capture vocale (optionnelle)
   - Upload ou enregistrement via `VoiceProcessor`.
   - Pipeline : chargement WAV -> suppression silence -> pré-emphase -> extraction MFCC (moyennes/écarts-types, delta, delta-delta) -> normalisation.

4. Validation du consentement
   - Avant persistance, vérifier `consent['consent_given']` et enregistrer la trace de consentement via `ComplianceManager.record_consent()`.

5. Stockage
   - Calculer `bio_hash = generate_biometric_hash(face_encoding, fingerprint_features)` (SHA-256) et stocker.
   - Chiffrer les templates : `encrypted_face = SecurityManager.encrypt_descriptor(face_encoding)` etc., puis écrire en JSON/PG.
   - Journaliser l'enrôlement via `AuditLogger.log_enrollment(operator_id, bio_id, modalities, ip)`.

---

## 14) Vérification (verify) - détail technique

Procédure 1:1 (vérifier qu'une personne est celle déclarée) :

1. Le client capture les features (face_encoding, fingerprint_features, voice_features) et appelle `/api/verify` avec `bio_id`.
2. `BioIDGenerator.verify_identity(bio_id, ...)` récupère le profil stocké :
   - si les templates sont chiffrés, les déchiffrer : `SecurityManager.decrypt_descriptor()`.
3. Comparaisons par modalité :
   - Face : distance euclidienne entre encodage fourni et encodage stocké. Distance <= threshold_face => match.
   - Empreinte : similarité cosinus entre vecteurs fingerprint_features ; similarité >= threshold_fp => match.
   - Voix : distance euclidienne entre vecteurs MFCC / features ; distance <= threshold_voice => match.
4. Conversion en confiance : les distances sont transformées en pourcentage de confiance (ex: confidence = max(0, min(100, (1 - distance) * 100))).
5. Fusion des décisions :
   - Comportement actuel du projet : si plusieurs modalités sont fournies, toutes doivent correspondre (`AND`) pour que `verified = True`.
   - Alternatives recommandées : score-level fusion (pondération et somme), thresholding combiné, ou classifier de fusion (logistic regression) pour améliorer précision.
6. Audit & métriques : journaliser l'événement (`AuditLogger.log_verification`) et, si demandé, appeler `metrics.record_verification(is_genuine, score, modality)` pour alimenter les calculs FAR/FRR/EER.

Notes sur landmarks :
- Les landmarks ne sont pas nécessaires pour la comparaison 128D (les encodages résument déjà les informations faciales). On utilise les landmarks si on souhaite : aligner/normaliser la face, détecter la pose, ou ajouter features supplémentaires (intra-face ratios). Stocker les landmarks augmente la surface d'attaque et n'est pas nécessaire pour la majorité des comparaisons.

---

## 15) Méthodes de décision et seuils

- Face : seuil typique `0.4-0.6` (0.4 stricte, 0.6 standard), déterminé empiriquement via métriques.
- Empreinte : pour vecteurs normalisés, similarité cosinus proche de 1 = bon, on peut utiliser `similarity >= 0.7-0.9` selon normalisation.
- Voix : distances MFCC sont plus élevées ; seuils plus laxistes (ex: 2.0 dans l'implémentation actuelle).

Choisir les seuils :
- Utiliser `metrics.calculate_far_frr(threshold, modality)` et `calculate_eer()` pour choisir un seuil qui équilibre sécurité et disponibilité.
- Décision en production : définir politique métier (sécurité forte = seuil faible pour FAR ; accessibilité = seuil plus permissif pour FRR) et potentiellement utiliser fusion multimodale.

---

## 16) Librairies & dépendances (par module) — pourquoi et valeur ajoutée

Remarque : noms des paquets pip approximatifs ; vérifier `requirements.txt` pour versions exactes.

- Application / Frontend (`app.py`)
  - Flask : framework web léger pour routes REST et templates.
  - Jinja2 (inclus) : templates HTML.
  - gunicorn (production) : serveur WSGI pour déployer l'app.
  - Valeur : orchestration des routes, middlewares, sessions.

- Traitement d'images & vidéo (`face_capture.py`, `fingerprint_processor.py`)
  - opencv-python (`cv2`) : capture vidéo, opérations d'image, enregistrement.
  - face_recognition (lib basée sur dlib) : détection de visage, encodages 128D, utilitaires.
  - dlib : modèles ML pour visage (si utilisé par face_recognition).
  - scikit-image : skeletonize et outils morphologiques pour empreintes.
  - Pillow (PIL) : manipulation d'images.
  - Valeur : robustesse du pipeline d'image, code existant pour extration de features biométriques.

- Traitement audio (`voice_processor.py`)
  - librosa : extraction MFCC et features audio.
  - sounddevice : enregistrement au runtime.
  - scipy : lecture/écriture WAV (scipy.io.wavfile).
  - Valeur : extraction de features vocales solides et répandues (MFCC).

- Sécurité et cryptographie (`security.py`)
  - cryptography (Fernet, PBKDF2HMAC) : chiffrement symétrique sécurisé.
  - bcrypt : hachage des mots de passe.
  - Valeur : protection des templates, hachage de mots de passe, intégrité.

- Base de données (`database.py`)
  - psycopg2 / psycopg2-binary : client PostgreSQL.
  - PyJWT (jwt) : création/validation JWT si géré depuis DB layer.
  - Valeur : stockage relationnel pour production, gestion utilisateurs et tokens.

- Audit & métriques (`audit.py`, `metrics.py`)
  - numpy : calculs et transformations.
  - scipy (opt) : outils pour interpolation/optimisation (pour EER si nécessaire).
  - Valeur : calculs statistiques, ingestion logs, rapports de biais.

- Empreinte digitale (`fingerprint_processor.py`)
  - scikit-image, opencv, numpy, pillow
  - Valeur : extraction minutiae, vecteurs de caractéristiques robustes pour empreintes.

- Général / utilitaires
  - requests (optionnel), tqdm, pandas (optionnel pour analyses), matplotlib (visualisation)

- Dépendences système (Dockerfile)
  - build-essential, cmake : compilation de dlib
  - ffmpeg, libsndfile1, portaudio19-dev : support audio
  - libgl1, libglib2.0-0, libsm6, libxext6, libxrender-dev : dépendences graphiques pour OpenCV

Valeur ajoutée globale de ces bibliothèques : elles fournissent des implémentations éprouvées d'algorithmes complexes (détection/encodage facial, extraction MFCC, traitement d'images), accélèrent le développement et assurent une meilleure reproductibilité et performance.

---

## 17) Verify 1:1 vs Identify 1:N — explication simple

- Verify 1:1 (one-to-one) :
  - But : confirmer qu'une personne présente correspond à une identité déclarée (bio_id fourni).
  - Entrée : features capturées + bio_id.
  - Opération : comparer features avec les templates correspondants au `bio_id` (comparaison directe). Retour : `verified` (True/False) et scores.
  - Usage typique : contrôle d'accès où l'utilisateur donne son identifiant (carte, ID) puis prouve son identité biométrique.

- Identify 1:N (one-to-many) :
  - But : retrouver l'identité d'une personne inconnue parmi une base de N personnes.
  - Entrée : features capturées (sans bio_id).
  - Opération : comparer le probe à tous (ou indexer la base) et renvoyer le meilleur match si au-dessus d'un seuil.
  - Usage typique : recherche d'une personne dans une base (police, triage d'enrôlement, détection d'entrées déjà existantes).

Différences techniques :
  - Complexité : 1:1 est O(1) (comparaison unique), 1:N est O(N) pour recherche naïve. Pour grands N, on utilise indexation (FAISS, Annoy, HNSW) pour nearest-neighbor rapide.
  - Seuils et confiance : pour 1:N on utilise souvent seuils plus stricts pour éviter faux-positifs (FAR), et pour la recherche de candidats on peut retourner top-K pour revue humaine.
  - Fusion multimodale : en 1:N, fusionner modalities aide à réduire le nombre de faux-positifs dans la recherche.

---

Fin de `project.md`.
