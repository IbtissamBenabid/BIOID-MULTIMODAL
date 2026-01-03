"""
Configuration du projet BioID
"""
import os

# Dossiers
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
FACES_DIR = os.path.join(DATA_DIR, "faces")
FINGERPRINTS_DIR = os.path.join(DATA_DIR, "fingerprints")
DATABASE_DIR = os.path.join(DATA_DIR, "database")

# Créer les dossiers s'ils n'existent pas
for directory in [DATA_DIR, FACES_DIR, FINGERPRINTS_DIR, DATABASE_DIR]:
    os.makedirs(directory, exist_ok=True)

# Paramètres capture faciale
FACE_CAPTURE_COUNT = 20  # Nombre de captures à prendre
FACE_DETECTION_MODEL = "hog"  # "hog" (rapide) ou "cnn" (précis)

# Paramètres empreinte digitale
FINGERPRINT_RESIZE = (300, 400)

# Base de données JSON simple pour le projet académique
DATABASE_FILE = os.path.join(DATABASE_DIR, "beneficiaries.json")
