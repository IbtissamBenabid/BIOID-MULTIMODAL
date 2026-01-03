# BioID - Système d'Identification Biométrique Sécurisé

Système d'identification biométrique multimodal conforme RGPD / Loi 09-08 pour l'identification des réfugiés et personnes sans papiers.

## 🎯 Fonctionnalités

### Biométrie Multimodale
- **Capture faciale temps réel** via webcam (10 captures pour plus de précision)
- **Analyse d'empreintes digitales** via upload de fichier image
- **Génération d'UUID unique** pour chaque bénéficiaire

### Sécurité & Conformité
- **Authentification RBAC** (Admin, Operator, Auditor, User)
- **Chiffrement AES-256** des descripteurs biométriques
- **Journalisation d'audit** complète et horodatée
- **Consentement RGPD** obligatoire à l'enrôlement
- **Tokens de session** sécurisés (8 heures)

### Interface Utilisateur
- **Page de connexion** sécurisée
- **Dashboard** avec statistiques
- **Interface responsive** Bootstrap 5

## 📁 Structure du Projet

```
bioid/
├── app_v2.py                   # Application Flask principale (sécurisée)
├── app.py                      # Version legacy
├── config.py                   # Configuration
├── requirements.txt            # Dépendances Python
├── modules/
│   ├── __init__.py
│   ├── face_capture.py         # Module capture faciale
│   ├── fingerprint_processor.py # Module empreintes digitales
│   ├── bioid_generator.py      # Génération UUID & vérification
│   ├── security.py             # Chiffrement & tokens
│   ├── audit.py                # Journalisation d'audit
│   ├── rbac.py                 # Gestion des rôles et permissions
│   └── metrics.py              # Métriques FAR/FRR/EER
├── templates/
│   ├── login.html              # Page de connexion
│   ├── index.html              # Page d'accueil
│   ├── enroll.html             # Page d'enrôlement
│   └── verify.html             # Page de vérification
├── data/
│   ├── faces/                  # Images faciales
│   ├── fingerprints/           # Images empreintes
│   ├── database/               # Base de données JSON
│   ├── security/               # Clés & utilisateurs
│   └── audit/                  # Logs d'audit
└── docs/
    └── CAS_USAGE.md            # Documentation détaillée
```

## 🚀 Installation

### 1. Créer un environnement virtuel

```bash
cd bioid
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

### 2. Installer les dépendances

```bash
pip install -r requirements.txt
```

> **Note**: L'installation de `dlib` peut nécessiter Visual Studio Build Tools sur Windows.
> Téléchargez-le ici: https://visualstudio.microsoft.com/visual-cpp-build-tools/

### 3. Lancer l'application

```bash
python app_v2.py
```

Accédez à **http://localhost:5000** dans votre navigateur.

## 🔐 Authentification

### Comptes par défaut

| Utilisateur | Mot de passe | Rôle | Permissions |
|-------------|--------------|------|-------------|
| `admin` | `admin123` | Admin | Toutes |
| `operator` | `op123` | Opérateur | Enrôlement, Vérification |
| `auditor` | `audit123` | Auditeur | Lecture seule, Audit |

### Flux d'authentification

1. Accès à `/` → Redirection vers `/login`
2. Connexion avec identifiants
3. Token stocké en cookie (8h de validité)
4. Accès aux fonctionnalités selon le rôle

## 📖 Utilisation

### Enrôlement d'un nouveau bénéficiaire

1. Connectez-vous (rôle: admin ou operator)
2. Allez sur la page **Enrôlement**
3. Entrez le nom du bénéficiaire
4. **Cochez les cases de consentement RGPD** (obligatoire)
5. Capturez **10 images** du visage via la webcam
6. Uploadez une image d'empreinte digitale
7. Cliquez sur **Enregistrer**
8. Un **ID biométrique unique** est généré (ex: `BIO-A1B2C3D4-E5F6`)

### Vérification d'identité

1. Allez sur la page **Vérification**
2. Entrez l'ID biométrique (ou sélectionnez dans la liste)
3. Capturez le visage et/ou uploadez l'empreinte
4. Cliquez sur **Vérifier**
5. Le système affiche le résultat avec les scores de confiance

## 🔧 Technologies Utilisées

| Technologie | Usage |
|-------------|-------|
| Python 3.8+ | Backend |
| Flask 3.0 | Serveur web REST API |
| OpenCV | Traitement d'images |
| face_recognition | Détection et encodage facial (128D) |
| dlib | Landmarks faciaux |
| scikit-image | Traitement empreintes |
| cryptography | Chiffrement Fernet/AES-256 |
| Bootstrap 5 | Interface utilisateur |

## 📊 Algorithmes

### Reconnaissance Faciale
- Détection de visage avec HOG (Histogram of Oriented Gradients)
- Encodage facial en vecteur 128D
- Comparaison par distance euclidienne (seuil: 0.6)
- Moyenne de 10 captures pour robustesse

### Empreintes Digitales
- Prétraitement: normalisation, CLAHE, binarisation adaptative
- Squelettisation pour extraction des minutiae
- Détection des terminaisons (1 voisin) et bifurcations (3 voisins)
- Comparaison par distance euclidienne (seuil: 0.3)

### Génération UUID
- UUID v4 aléatoire (unicité garantie)
- Format: `BIO-XXXXXXXX-XXXX`

## 🛡️ Sécurité

### Conformité RGPD / Loi 09-08
- Consentement explicite obligatoire
- Droit à l'effacement (suppression des données)
- Journalisation complète des accès
- Pseudonymisation des identifiants

### Chiffrement
- Descripteurs biométriques chiffrés AES-256
- Clés stockées séparément
- Tokens de session signés

### Audit
- Logs horodatés par jour
- Événements: enrôlement, vérification, accès, connexion
- IP source enregistrée
- Export possible pour conformité

## 📈 API REST

### Authentification
- `POST /api/auth/login` - Connexion
- `POST /api/auth/logout` - Déconnexion
- `GET /api/auth/me` - Infos utilisateur courant

### Biométrie
- `POST /api/capture_face` - Capture faciale
- `POST /api/process_fingerprint` - Traitement empreinte
- `POST /api/register` - Enrôlement
- `POST /api/verify` - Vérification 1:1
- `POST /api/identify` - Identification 1:N

### Données
- `GET /api/beneficiaries` - Liste bénéficiaires
- `GET /api/beneficiary/<id>` - Détail bénéficiaire
- `DELETE /api/beneficiary/<id>` - Suppression (RGPD)

### Audit
- `GET /api/audit/logs` - Logs d'audit
- `GET /api/audit/stats` - Statistiques

## ⚠️ Notes

- **Projet académique** - Non destiné à la production
- Les mots de passe par défaut doivent être changés
- Les empreintes sont via upload d'image (pas de capteur réel)
- Base de données JSON (pas de SGBD)

## 📄 Licence

Projet académique - Confiance Numérique 2025-2026
