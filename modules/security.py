"""
Module de sécurité et cryptographie
Chiffrement des descripteurs, protection des données biométriques
"""
import os
import hashlib
import hmac
import base64
import json
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import numpy as np


class SecurityManager:
    """Gère la sécurité et le chiffrement des données biométriques"""
    
    def __init__(self, secret_key=None, key_file="data/keys/master.key"):
        """
        Args:
            secret_key: Clé secrète (si None, générée ou chargée)
            key_file: Fichier de stockage de la clé
        """
        self.key_file = key_file
        self.secret_key = secret_key or self._load_or_generate_key()
        self.fernet = Fernet(self._derive_key(self.secret_key))
    
    def _load_or_generate_key(self):
        """Charge ou génère la clé maître"""
        os.makedirs(os.path.dirname(self.key_file), exist_ok=True)
        
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                return f.read()
        else:
            key = os.urandom(32)
            with open(self.key_file, 'wb') as f:
                f.write(key)
            print(f"[SECURITY] Nouvelle clé maître générée: {self.key_file}")
            return key
    
    def _derive_key(self, secret):
        """Dérive une clé Fernet à partir du secret"""
        salt = b'bioid_salt_v1'  # En production: utiliser un salt unique par installation
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(secret))
        return key
    
    def encrypt_descriptor(self, descriptor):
        """
        Chiffre un descripteur biométrique
        
        Args:
            descriptor: numpy array ou liste de caractéristiques
            
        Returns:
            str: Descripteur chiffré (base64)
        """
        if descriptor is None:
            return None
        
        # Convertir en bytes
        if isinstance(descriptor, np.ndarray):
            descriptor = descriptor.tolist()
        
        data = json.dumps(descriptor).encode()
        encrypted = self.fernet.encrypt(data)
        
        return base64.b64encode(encrypted).decode()
    
    def decrypt_descriptor(self, encrypted_descriptor):
        """
        Déchiffre un descripteur biométrique
        
        Args:
            encrypted_descriptor: Descripteur chiffré (base64)
            
        Returns:
            list: Descripteur déchiffré
        """
        if encrypted_descriptor is None:
            return None
        
        encrypted = base64.b64decode(encrypted_descriptor.encode())
        decrypted = self.fernet.decrypt(encrypted)
        
        return json.loads(decrypted.decode())
    
    def hash_biometric(self, data):
        """
        Génère un hash irréversible d'une donnée biométrique
        Pour la détection de doublons sans stocker les données brutes
        
        Args:
            data: Donnée à hasher
            
        Returns:
            str: Hash SHA-256
        """
        if data is None:
            return None
        
        if isinstance(data, np.ndarray):
            data = data.tobytes()
        elif isinstance(data, list):
            data = json.dumps(data).encode()
        elif isinstance(data, str):
            data = data.encode()
        
        return hashlib.sha256(data).hexdigest()
    
    def generate_token(self, bio_id, expiry_hours=24):
        """
        Génère un token d'authentification temporaire
        
        Args:
            bio_id: ID biométrique
            expiry_hours: Durée de validité en heures
            
        Returns:
            str: Token signé
        """
        expiry = datetime.now().timestamp() + (expiry_hours * 3600)
        payload = f"{bio_id}:{expiry}"
        
        signature = hmac.new(
            self.secret_key,
            payload.encode(),
            hashlib.sha256
        ).hexdigest()
        
        token = base64.b64encode(f"{payload}:{signature}".encode()).decode()
        return token
    
    def verify_token(self, token):
        """
        Vérifie un token d'authentification
        
        Args:
            token: Token à vérifier
            
        Returns:
            tuple: (valid: bool, bio_id: str or None)
        """
        try:
            decoded = base64.b64decode(token.encode()).decode()
            bio_id, expiry, signature = decoded.rsplit(':', 2)
            
            # Vérifier la signature
            expected_sig = hmac.new(
                self.secret_key,
                f"{bio_id}:{expiry}".encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(signature, expected_sig):
                return False, None
            
            # Vérifier l'expiration
            if float(expiry) < datetime.now().timestamp():
                return False, None
            
            return True, bio_id
            
        except Exception:
            return False, None
    
    def pseudonymize_id(self, original_id):
        """
        Génère un pseudonyme pour un ID (RGPD)
        
        Args:
            original_id: ID original
            
        Returns:
            str: Pseudonyme
        """
        return hmac.new(
            self.secret_key,
            original_id.encode(),
            hashlib.sha256
        ).hexdigest()[:16]


class DataProtection:
    """Gestion de la protection des données (RGPD/Loi 09-08)"""
    
    @staticmethod
    def get_consent_template():
        """Retourne le template de consentement"""
        return {
            "version": "1.0",
            "date": None,
            "purposes": [
                "authentication",  # Authentification biométrique
                "identification",  # Identification dans le système
                "audit"           # Traçabilité et audit
            ],
            "retention_days": 365,  # Durée de conservation
            "rights": [
                "access",      # Droit d'accès
                "rectification",  # Droit de rectification
                "deletion",    # Droit à l'effacement
                "portability"  # Droit à la portabilité
            ],
            "consent_given": False,
            "consent_method": None,  # "explicit", "digital_signature"
            "withdraw_date": None
        }
    
    @staticmethod
    def validate_consent(consent_data):
        """Valide les données de consentement"""
        required = ["date", "consent_given", "consent_method"]
        return all(consent_data.get(k) for k in required)
    
    @staticmethod
    def anonymize_record(record):
        """
        Anonymise un enregistrement pour export/audit
        
        Args:
            record: Enregistrement bénéficiaire
            
        Returns:
            dict: Enregistrement anonymisé
        """
        return {
            "id_hash": hashlib.sha256(record.get("bio_id", "").encode()).hexdigest()[:12],
            "registration_date": record.get("registration_date"),
            "status": record.get("status"),
            "has_face": record.get("face_encoding") is not None,
            "has_fingerprint": record.get("fingerprint_features") is not None,
            "has_voice": record.get("voice_features") is not None,
        }


# Test du module
if __name__ == "__main__":
    print("=== Test du module de sécurité ===")
    
    security = SecurityManager()
    
    # Test chiffrement
    test_descriptor = [0.1, 0.2, 0.3, 0.4, 0.5]
    encrypted = security.encrypt_descriptor(test_descriptor)
    print(f"[OK] Chiffré: {encrypted[:50]}...")
    
    decrypted = security.decrypt_descriptor(encrypted)
    print(f"[OK] Déchiffré: {decrypted}")
    
    # Test token
    token = security.generate_token("BIO-12345678-ABCD")
    print(f"[OK] Token: {token[:50]}...")
    
    valid, bio_id = security.verify_token(token)
    print(f"[OK] Token valide: {valid}, ID: {bio_id}")
    
    # Test hash
    hash_result = security.hash_biometric(test_descriptor)
    print(f"[OK] Hash: {hash_result}")
