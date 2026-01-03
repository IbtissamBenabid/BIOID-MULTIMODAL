"""
Module de traitement des empreintes digitales
Upload et extraction des caractéristiques (minutiae)
"""
import cv2
import numpy as np
from PIL import Image
import os
from skimage.morphology import skeletonize
from skimage import img_as_ubyte


class FingerprintProcessor:
    """Gère le traitement et l'extraction des caractéristiques d'empreintes"""
    
    def __init__(self):
        self.image = None
        self.processed_image = None
        self.minutiae = []
        self.features = None
        
    def load_image(self, filepath):
        """
        Charge une image d'empreinte digitale
        
        Args:
            filepath: Chemin vers le fichier image
            
        Returns:
            bool: True si chargement réussi
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Fichier non trouvé: {filepath}")
        
        self.image = cv2.imread(filepath, cv2.IMREAD_GRAYSCALE)
        
        if self.image is None:
            raise ValueError("Impossible de charger l'image")
        
        print(f"[OK] Image chargée: {self.image.shape}")
        return True
    
    def load_from_bytes(self, image_bytes):
        """
        Charge une image depuis des bytes (pour upload web)
        
        Args:
            image_bytes: Bytes de l'image
        """
        nparr = np.frombuffer(image_bytes, np.uint8)
        self.image = cv2.imdecode(nparr, cv2.IMREAD_GRAYSCALE)
        
        if self.image is None:
            raise ValueError("Impossible de décoder l'image")
        
        return True
    
    def preprocess(self):
        """
        Prétraitement de l'image d'empreinte
        - Redimensionnement
        - Normalisation
        - Amélioration du contraste
        - Binarisation
        """
        if self.image is None:
            raise ValueError("Aucune image chargée")
        
        # Redimensionner
        img = cv2.resize(self.image, (300, 400))
        
        # Normalisation
        img = cv2.normalize(img, None, 0, 255, cv2.NORM_MINMAX)
        
        # Amélioration du contraste avec CLAHE
        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        img = clahe.apply(img)
        
        # Flou gaussien pour réduire le bruit
        img = cv2.GaussianBlur(img, (5, 5), 0)
        
        # Binarisation adaptative
        img = cv2.adaptiveThreshold(
            img, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, 
            cv2.THRESH_BINARY_INV, 11, 2
        )
        
        # Opérations morphologiques pour nettoyer
        kernel = np.ones((3, 3), np.uint8)
        img = cv2.morphologyEx(img, cv2.MORPH_CLOSE, kernel)
        img = cv2.morphologyEx(img, cv2.MORPH_OPEN, kernel)
        
        self.processed_image = img
        print("[OK] Prétraitement terminé")
        
        return img
    
    def extract_minutiae(self):
        """
        Extrait les minutiae (points caractéristiques) de l'empreinte
        - Terminaisons de crêtes
        - Bifurcations
        
        Returns:
            list: Liste des minutiae [(x, y, type, angle), ...]
        """
        if self.processed_image is None:
            self.preprocess()
        
        # Squelettisation
        skeleton = skeletonize(self.processed_image // 255)
        skeleton = img_as_ubyte(skeleton)
        
        self.minutiae = []
        
        # Parcourir l'image pour détecter les minutiae
        rows, cols = skeleton.shape
        
        for i in range(1, rows - 1):
            for j in range(1, cols - 1):
                if skeleton[i, j] == 255:  # Point sur une crête
                    # Compter les voisins (8-connexité)
                    neighbors = self._count_neighbors(skeleton, i, j)
                    
                    # Terminaison: 1 voisin
                    if neighbors == 1:
                        angle = self._calculate_angle(skeleton, i, j)
                        self.minutiae.append((j, i, 'termination', angle))
                    
                    # Bifurcation: 3 voisins
                    elif neighbors == 3:
                        angle = self._calculate_angle(skeleton, i, j)
                        self.minutiae.append((j, i, 'bifurcation', angle))
        
        # Filtrer les minutiae trop proches des bords
        margin = 20
        self.minutiae = [
            m for m in self.minutiae 
            if margin < m[0] < cols - margin and margin < m[1] < rows - margin
        ]
        
        print(f"[OK] {len(self.minutiae)} minutiae extraites")
        return self.minutiae
    
    def _count_neighbors(self, img, i, j):
        """Compte les voisins blancs d'un pixel"""
        neighbors = [
            img[i-1, j-1], img[i-1, j], img[i-1, j+1],
            img[i, j-1],               img[i, j+1],
            img[i+1, j-1], img[i+1, j], img[i+1, j+1]
        ]
        return sum(1 for n in neighbors if n == 255)
    
    def _calculate_angle(self, img, i, j):
        """Calcule l'angle d'orientation d'une minutiae"""
        # Trouver le voisin connecté
        for di in [-1, 0, 1]:
            for dj in [-1, 0, 1]:
                if di == 0 and dj == 0:
                    continue
                if img[i + di, j + dj] == 255:
                    return np.arctan2(di, dj)
        return 0
    
    def extract_features(self):
        """
        Extrait un vecteur de caractéristiques de l'empreinte
        Combine plusieurs métriques pour créer une signature unique
        
        Returns:
            numpy.ndarray: Vecteur de caractéristiques
        """
        if not self.minutiae:
            self.extract_minutiae()
        
        features = []
        
        # Nombre de minutiae par type
        terminations = [m for m in self.minutiae if m[2] == 'termination']
        bifurcations = [m for m in self.minutiae if m[2] == 'bifurcation']
        
        features.append(len(terminations))
        features.append(len(bifurcations))
        features.append(len(self.minutiae))
        
        if self.minutiae:
            # Positions moyennes
            x_coords = [m[0] for m in self.minutiae]
            y_coords = [m[1] for m in self.minutiae]
            
            features.extend([
                np.mean(x_coords), np.std(x_coords),
                np.mean(y_coords), np.std(y_coords)
            ])
            
            # Angles moyens
            angles = [m[3] for m in self.minutiae]
            features.extend([np.mean(angles), np.std(angles)])
            
            # Distances entre minutiae
            if len(self.minutiae) > 1:
                distances = []
                for i in range(min(len(self.minutiae), 50)):
                    for j in range(i + 1, min(len(self.minutiae), 50)):
                        d = np.sqrt(
                            (self.minutiae[i][0] - self.minutiae[j][0])**2 +
                            (self.minutiae[i][1] - self.minutiae[j][1])**2
                        )
                        distances.append(d)
                
                features.extend([
                    np.mean(distances), np.std(distances),
                    np.min(distances), np.max(distances)
                ])
            else:
                features.extend([0, 0, 0, 0])
        else:
            features.extend([0] * 11)
        
        # Histogramme d'orientation
        if self.processed_image is not None:
            # Calculer les gradients
            gx = cv2.Sobel(self.processed_image, cv2.CV_64F, 1, 0, ksize=3)
            gy = cv2.Sobel(self.processed_image, cv2.CV_64F, 0, 1, ksize=3)
            
            # Orientations
            orientations = np.arctan2(gy, gx)
            hist, _ = np.histogram(orientations.flatten(), bins=16, range=(-np.pi, np.pi))
            hist = hist / (np.sum(hist) + 1e-7)  # Normaliser
            features.extend(hist.tolist())
        
        self.features = np.array(features, dtype=np.float32)
        
        # Normaliser le vecteur final
        norm = np.linalg.norm(self.features)
        if norm > 0:
            self.features = self.features / norm
        
        print(f"[OK] Vecteur de caractéristiques extrait: {len(self.features)} dimensions")
        return self.features
    
    def visualize(self, save_path=None):
        """
        Visualise l'empreinte avec les minutiae détectées
        
        Args:
            save_path: Chemin pour sauvegarder (optionnel)
        """
        if self.processed_image is None:
            self.preprocess()
        
        # Convertir en couleur pour afficher les minutiae
        vis = cv2.cvtColor(self.processed_image, cv2.COLOR_GRAY2BGR)
        
        for x, y, mtype, angle in self.minutiae:
            if mtype == 'termination':
                color = (0, 255, 0)  # Vert pour terminaisons
            else:
                color = (0, 0, 255)  # Rouge pour bifurcations
            
            cv2.circle(vis, (x, y), 3, color, -1)
        
        # Légende
        cv2.putText(vis, f"Terminations: {len([m for m in self.minutiae if m[2] == 'termination'])}", 
                   (10, 20), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 0), 1)
        cv2.putText(vis, f"Bifurcations: {len([m for m in self.minutiae if m[2] == 'bifurcation'])}", 
                   (10, 40), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 255), 1)
        
        if save_path:
            cv2.imwrite(save_path, vis)
            print(f"[OK] Visualisation sauvegardée: {save_path}")
        
        cv2.imshow("Fingerprint Analysis - BioID", vis)
        cv2.waitKey(0)
        cv2.destroyAllWindows()
        
        return vis


def compare_fingerprints(features1, features2, threshold=0.3):
    """
    Compare deux empreintes digitales
    
    Args:
        features1: Vecteur de caractéristiques 1
        features2: Vecteur de caractéristiques 2
        threshold: Seuil de similarité
        
    Returns:
        tuple: (match: bool, similarity: float)
    """
    if features1 is None or features2 is None:
        return False, 0.0
    
    # Distance cosinus
    similarity = np.dot(features1, features2) / (
        np.linalg.norm(features1) * np.linalg.norm(features2) + 1e-7
    )
    
    match = similarity >= (1 - threshold)
    
    return match, similarity


# Test du module
if __name__ == "__main__":
    print("=== Test du module empreintes digitales ===")
    print("Veuillez fournir le chemin d'une image d'empreinte:")
    
    # Test avec une image exemple
    test_path = input("Chemin de l'image: ").strip()
    
    if test_path and os.path.exists(test_path):
        processor = FingerprintProcessor()
        processor.load_image(test_path)
        processor.preprocess()
        processor.extract_minutiae()
        features = processor.extract_features()
        
        print(f"\n[OK] Extraction terminée")
        print(f"[OK] Nombre de minutiae: {len(processor.minutiae)}")
        print(f"[OK] Dimension du vecteur: {len(features)}")
        
        processor.visualize()
    else:
        print("[INFO] Aucune image fournie ou fichier introuvable")
