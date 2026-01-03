# BioID - Système d'Identification Biométrique

Projet académique de sécurité biométrique basé sur la reconnaissance faciale et les empreintes digitales pour l'identification des réfugiés et personnes sans papiers.

## 🎯 Fonctionnalités

- **Capture faciale temps réel** via webcam (5 captures pour plus de précision)
- **Analyse d'empreintes digitales** via upload de fichier image
- **Génération d'UUID unique** basé sur les données biométriques
- **Vérification d'identité** par comparaison biométrique
- **Interface web** simple et intuitive

## 📁 Structure du Projet

```
bioid/
├── app.py                      # Application Flask principale
├── config.py                   # Configuration
├── requirements.txt            # Dépendances Python
├── modules/
│   ├── __init__.py
│   ├── face_capture.py         # Module capture faciale
│   ├── fingerprint_processor.py # Module empreintes digitales
│   └── bioid_generator.py      # Génération UUID
├── templates/
│   ├── index.html              # Page d'accueil
│   ├── enroll.html             # Page d'enrôlement
│   └── verify.html             # Page de vérification
└── data/
    ├── faces/                  # Images faciales
    ├── fingerprints/           # Images empreintes
    └── database/               # Base de données JSON
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
python app.py
```

Accédez à **http://localhost:5000** dans votre navigateur.

## 📖 Utilisation

### Enrôlement d'un nouveau bénéficiaire

1. Allez sur la page **Enrôlement**
2. Entrez le nom du bénéficiaire
3. Capturez 5 images du visage via la webcam
4. Uploadez une image d'empreinte digitale
5. Cliquez sur **Enregistrer**
6. Un **ID biométrique unique** est généré (ex: `BIO-A1B2C3D4-E5F6`)

### Vérification d'identité

1. Allez sur la page **Vérification**
2. Entrez l'ID biométrique
3. Capturez le visage et/ou uploadez l'empreinte
4. Cliquez sur **Vérifier**
5. Le système affiche si l'identité correspond

## 🔧 Technologies Utilisées

| Technologie | Usage |
|-------------|-------|
| Python 3.8+ | Backend |
| Flask | Serveur web |
| OpenCV | Traitement d'images |
| face_recognition | Détection et encodage facial |
| dlib | Landmarks faciaux |
| scikit-image | Traitement empreintes |
| Bootstrap 5 | Interface utilisateur |

## 📊 Algorithmes

### Reconnaissance Faciale
- Détection de visage avec HOG (Histogram of Oriented Gradients)
- Encodage facial en vecteur 128D
- Comparaison par distance euclidienne (seuil: 0.6)

### Empreintes Digitales
- Prétraitement: normalisation, CLAHE, binarisation adaptative
- Squelettisation pour extraction des minutiae
- Détection des terminaisons (1 voisin) et bifurcations (3 voisins)
- Comparaison par similarité cosinus

### Génération UUID
- Hash SHA-256 des données biométriques combinées
- UUID v5 déterministe basé sur le hash biométrique
- Format: `BIO-XXXXXXXX-XXXX`

## ⚠️ Limitations (Projet Académique)

- Base de données JSON simple (pas de chiffrement en production)
- Pas de gestion des sessions utilisateur
- Empreintes via upload d'image (pas de capteur réel)
- Non adapté à un déploiement en production

## 📄 Licence

Projet académique - Confiance Numérique
