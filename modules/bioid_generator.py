"""
Module de génération d'identifiants uniques
Génère un UUID basé sur les données biométriques
"""
import uuid
import hashlib
import numpy as np
import json
import os
from datetime import datetime


class BioIDGenerator:
    """Génère des identifiants uniques basés sur les données biométriques"""
    
    def __init__(self, database_path="data/database/beneficiaries.json"):
        self.database_path = database_path
        self.database = self._load_database()
    
    def _load_database(self):
        """Charge la base de données JSON"""
        if os.path.exists(self.database_path):
            with open(self.database_path, 'r') as f:
                return json.load(f)
        return {"beneficiaries": []}
    
    def _save_database(self):
        """Sauvegarde la base de données JSON"""
        os.makedirs(os.path.dirname(self.database_path), exist_ok=True)
        with open(self.database_path, 'w') as f:
            json.dump(self.database, f, indent=2)
    
    def reload_database(self):
        """Recharge la base de données depuis le fichier JSON"""
        self.database = self._load_database()
        return self.database
    
    def generate_biometric_hash(self, face_encoding, fingerprint_features):
        """
        Génère un hash unique basé sur les caractéristiques biométriques
        
        Args:
            face_encoding: Encodage facial (numpy array 128D)
            fingerprint_features: Caractéristiques empreinte (numpy array)
            
        Returns:
            str: Hash biométrique unique
        """
        # Combiner les deux vecteurs biométriques
        combined = np.concatenate([
            face_encoding.flatten() if face_encoding is not None else np.zeros(128),
            fingerprint_features.flatten() if fingerprint_features is not None else np.zeros(30)
        ])
        
        # Convertir en bytes et hasher
        bio_bytes = combined.tobytes()
        bio_hash = hashlib.sha256(bio_bytes).hexdigest()
        
        return bio_hash
    
    def generate_uuid(self, face_encoding=None, fingerprint_features=None, prefix="BIO"):
        """
        Génère un UUID unique pour un bénéficiaire
        Toujours génère un nouvel UUID aléatoire unique
        
        Args:
            face_encoding: Encodage facial (non utilisé pour l'UUID)
            fingerprint_features: Caractéristiques empreinte (non utilisé pour l'UUID)
            prefix: Préfixe de l'identifiant
            
        Returns:
            str: Identifiant unique format "BIO-XXXXXXXX-XXXX"
        """
        # Toujours générer un UUID aléatoire unique (uuid4)
        base_uuid = uuid.uuid4()
        
        # Formater l'identifiant
        uuid_str = str(base_uuid).upper()
        short_id = f"{prefix}-{uuid_str[:8]}-{uuid_str[9:13]}"
        
        # Vérifier que l'ID n'existe pas déjà dans la base
        while self.find_by_id(short_id) is not None:
            base_uuid = uuid.uuid4()
            uuid_str = str(base_uuid).upper()
            short_id = f"{prefix}-{uuid_str[:8]}-{uuid_str[9:13]}"
        
        return short_id
    
    def register_beneficiary(self, name, face_encoding, fingerprint_features, metadata=None):
        """
        Enregistre un nouveau bénéficiaire dans le système
        Chaque enregistrement génère toujours un nouvel ID unique
        
        Args:
            name: Nom du bénéficiaire
            face_encoding: Encodage facial (numpy array)
            fingerprint_features: Caractéristiques empreinte (numpy array)
            metadata: Informations additionnelles (optionnel)
            
        Returns:
            dict: Informations du bénéficiaire enregistré
        """
        # NOTE: Anti-doublon désactivé - chaque enregistrement crée un nouvel ID
        # Si vous voulez réactiver la vérification anti-doublon, décommentez:
        # existing = self.find_by_biometrics(face_encoding, fingerprint_features)
        # if existing:
        #     print(f"[ATTENTION] Bénéficiaire déjà enregistré: {existing['bio_id']}")
        #     return existing
        
        # Générer l'identifiant unique (toujours nouveau)
        bio_id = self.generate_uuid(face_encoding, fingerprint_features)
        bio_hash = self.generate_biometric_hash(face_encoding, fingerprint_features)
        
        # Créer l'enregistrement
        beneficiary = {
            "bio_id": bio_id,
            "name": name,
            "registration_date": datetime.now().isoformat(),
            "bio_hash": bio_hash,
            "face_encoding": face_encoding.tolist() if face_encoding is not None else None,
            "fingerprint_features": fingerprint_features.tolist() if fingerprint_features is not None else None,
            "metadata": metadata or {},
            "status": "active"
        }
        
        # Ajouter à la base de données
        self.database["beneficiaries"].append(beneficiary)
        self._save_database()
        
        print(f"[OK] Bénéficiaire enregistré: {bio_id}")
        return beneficiary
    
    def find_by_id(self, bio_id):
        """
        Recherche un bénéficiaire par son ID
        
        Args:
            bio_id: Identifiant biométrique
            
        Returns:
            dict: Informations du bénéficiaire ou None
        """
        for beneficiary in self.database["beneficiaries"]:
            if beneficiary["bio_id"] == bio_id:
                return beneficiary
        return None
    
    # Alias pour compatibilité
    def get_beneficiary(self, bio_id):
        """Alias pour find_by_id"""
        return self.find_by_id(bio_id)
    
    def find_by_biometrics(self, face_encoding, fingerprint_features, 
                           face_threshold=0.6, fingerprint_threshold=0.6):
        """
        Recherche un bénéficiaire par ses données biométriques
        
        Args:
            face_encoding: Encodage facial à comparer
            fingerprint_features: Caractéristiques empreinte à comparer
            face_threshold: Seuil de distance faciale (plus bas = plus strict)
            fingerprint_threshold: Seuil de similarité empreinte (plus haut = plus strict)
            
        Returns:
            dict: Bénéficiaire correspondant ou None
        """
        best_match = None
        best_face_distance = float('inf')
        best_fp_similarity = 0
        
        for beneficiary in self.database["beneficiaries"]:
            face_match = False
            fingerprint_match = False
            current_face_distance = float('inf')
            current_fp_similarity = 0
            
            # Comparaison faciale
            if face_encoding is not None and beneficiary["face_encoding"] is not None:
                stored_face = np.array(beneficiary["face_encoding"])
                face_enc = np.array(face_encoding)
                current_face_distance = np.linalg.norm(face_enc - stored_face)
                face_match = current_face_distance <= face_threshold
            
            # Comparaison empreinte
            if fingerprint_features is not None and beneficiary["fingerprint_features"] is not None:
                stored_fp = np.array(beneficiary["fingerprint_features"])
                fp_feat = np.array(fingerprint_features)
                norm_product = np.linalg.norm(fp_feat) * np.linalg.norm(stored_fp)
                if norm_product > 1e-7:
                    current_fp_similarity = np.dot(fp_feat, stored_fp) / norm_product
                fingerprint_match = current_fp_similarity >= fingerprint_threshold
            
            # Au moins une correspondance
            if face_match or fingerprint_match:
                # Garder le meilleur match
                if face_match and current_face_distance < best_face_distance:
                    best_match = beneficiary
                    best_face_distance = current_face_distance
                elif fingerprint_match and current_fp_similarity > best_fp_similarity:
                    best_match = beneficiary
                    best_fp_similarity = current_fp_similarity
        
        return best_match
    
    def verify_identity(self, bio_id, face_encoding=None, fingerprint_features=None):
        """
        Vérifie l'identité d'un bénéficiaire
        
        Args:
            bio_id: Identifiant à vérifier
            face_encoding: Encodage facial capturé
            fingerprint_features: Caractéristiques empreinte capturées
            
        Returns:
            dict: Résultat de la vérification
        """
        beneficiary = self.find_by_id(bio_id)
        
        if not beneficiary:
            return {
                "verified": False,
                "error": "Identifiant non trouvé",
                "bio_id": bio_id
            }
        
        result = {
            "verified": False,
            "bio_id": bio_id,
            "name": beneficiary["name"],
            "face_match": None,
            "fingerprint_match": None,
            "face_confidence": 0,
            "fingerprint_confidence": 0
        }
        
        has_face_data = False
        has_fingerprint_data = False
        
        # Vérification faciale
        if face_encoding is not None and beneficiary["face_encoding"] is not None:
            has_face_data = True
            stored_face = np.array(beneficiary["face_encoding"])
            face_enc = np.array(face_encoding)
            
            # Calculer la distance euclidienne
            distance = np.linalg.norm(face_enc - stored_face)
            
            # Seuil de tolérance pour face_recognition
            # 0.4 = strict (même personne certaine)
            # 0.6 = standard
            # 0.7 = tolérant (recommandé pour conditions variées)
            face_threshold = 0.7
            result["face_match"] = bool(distance <= face_threshold)  # Convertir en Python bool
            result["face_distance"] = float(distance)  # Pour debug
            
            # Confiance: transformer distance en pourcentage
            # Plus la distance est faible, plus la confiance est élevée
            result["face_confidence"] = float(max(0, min(100, (1 - distance) * 100)))
            
            print(f"[DEBUG] Face distance: {distance:.4f}, threshold: {face_threshold}, match: {result['face_match']}")
        
        # Vérification empreinte
        if fingerprint_features is not None and beneficiary["fingerprint_features"] is not None:
            has_fingerprint_data = True
            stored_fp = np.array(beneficiary["fingerprint_features"])
            fp_feat = np.array(fingerprint_features)
            
            # Méthode 1: Distance euclidienne (comme pour le visage)
            fp_distance = np.linalg.norm(fp_feat - stored_fp)
            
            # Méthode 2: Similarité cosinus
            norm_product = np.linalg.norm(fp_feat) * np.linalg.norm(stored_fp)
            if norm_product > 1e-7:
                cosine_similarity = np.dot(fp_feat, stored_fp) / norm_product
            else:
                cosine_similarity = 0
            
            # Utiliser la distance euclidienne avec un seuil strict
            # Pour des vecteurs normalisés de ~29 dimensions, une distance < 0.3 = très similaire
            fingerprint_distance_threshold = 0.3
            result["fingerprint_match"] = bool(fp_distance <= fingerprint_distance_threshold)
            result["fingerprint_confidence"] = float(max(0, min(100, (1 - fp_distance) * 100)))
            result["fingerprint_distance"] = float(fp_distance)
            result["fingerprint_cosine"] = float(cosine_similarity)
            
            print(f"[DEBUG] Fingerprint distance: {fp_distance:.4f}, cosine: {cosine_similarity:.4f}, threshold: {fingerprint_distance_threshold}, match: {result['fingerprint_match']}")
        
        # Vérification globale
        # Si les deux données sont fournies, LES DEUX doivent correspondre
        # Si une seule donnée est fournie, elle doit correspondre
        if has_face_data and has_fingerprint_data:
            # Les deux données fournies - LES DEUX doivent matcher (sécurité renforcée)
            result["verified"] = bool(result["face_match"] and result["fingerprint_match"])
        elif has_face_data:
            result["verified"] = bool(result["face_match"])
        elif has_fingerprint_data:
            result["verified"] = bool(result["fingerprint_match"])
        else:
            result["error"] = "Aucune donnée biométrique fournie pour la vérification"
        
        print(f"[DEBUG] FINAL RESULT: verified={result['verified']}, face_match={result['face_match']}, fp_match={result['fingerprint_match']}")
        print(f"[DEBUG] has_face={has_face_data}, has_fp={has_fingerprint_data}")
        
        return result
    
    def get_all_beneficiaries(self):
        """Retourne la liste de tous les bénéficiaires"""
        return [
            {
                "bio_id": b["bio_id"],
                "name": b["name"],
                "registration_date": b["registration_date"],
                "status": b["status"]
            }
            for b in self.database["beneficiaries"]
        ]
    
    def get_statistics(self):
        """Retourne les statistiques de la base"""
        total = len(self.database["beneficiaries"])
        active = len([b for b in self.database["beneficiaries"] if b["status"] == "active"])
        
        return {
            "total_beneficiaries": total,
            "active": active,
            "inactive": total - active
        }


# Test du module
if __name__ == "__main__":
    print("=== Test du module de génération d'UUID ===")
    
    generator = BioIDGenerator()
    
    # Test avec des données simulées
    fake_face = np.random.randn(128)
    fake_fingerprint = np.random.randn(30)
    
    # Générer un UUID
    bio_id = generator.generate_uuid(fake_face, fake_fingerprint)
    print(f"\n[OK] UUID généré: {bio_id}")
    
    # Enregistrer un bénéficiaire test
    beneficiary = generator.register_beneficiary(
        name="Test User",
        face_encoding=fake_face,
        fingerprint_features=fake_fingerprint,
        metadata={"origin": "test"}
    )
    
    print(f"[OK] Bénéficiaire enregistré: {beneficiary['bio_id']}")
    
    # Vérifier l'identité
    result = generator.verify_identity(bio_id, fake_face, fake_fingerprint)
    print(f"[OK] Vérification: {result}")
    
    # Statistiques
    stats = generator.get_statistics()
    print(f"[OK] Statistiques: {stats}")
