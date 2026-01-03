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

# Base de données PostgreSQL (Production)
DATABASE_URL = "postgres://avnadmin:AVNS_PrGBoC-fUef_dB6Hakl@pg-39221806-etu-2442.d.aivencloud.com:22238/bioid?sslmode=require"

# JWT Configuration
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'bioid-jwt-secret-key-2026')
JWT_ALGORITHM = 'HS256'
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 30
JWT_REFRESH_TOKEN_EXPIRE_DAYS = 7
