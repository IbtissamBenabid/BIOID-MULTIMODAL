"""
Module de capture et traitement facial
Capture multiple en temps réel via webcam
"""
import cv2
import numpy as np
import face_recognition
import os
from datetime import datetime


class FaceCapture:
    """Gère la capture et l'extraction des caractéristiques faciales"""
    
    def __init__(self, capture_count=5):
        """
        Args:
            capture_count: Nombre de captures à effectuer
        """
        self.capture_count = capture_count
        self.captures = []
        self.encodings = []
        
    def start_capture(self, camera_index=0):
        """
        Lance la capture faciale en temps réel
        
        Args:
            camera_index: Index de la caméra (0 = webcam par défaut)
            
        Returns:
            list: Liste des encodages faciaux capturés
        """
        cap = cv2.VideoCapture(camera_index)
        
        if not cap.isOpened():
            raise Exception("Impossible d'accéder à la caméra")
        
        self.captures = []
        self.encodings = []
        captured_count = 0
        
        print(f"[INFO] Capture faciale - Appuyez sur ESPACE pour capturer ({self.capture_count} captures nécessaires)")
        print("[INFO] Appuyez sur 'Q' pour quitter")
        
        while captured_count < self.capture_count:
            ret, frame = cap.read()
            if not ret:
                continue
            
            # Miroir pour une meilleure expérience utilisateur
            frame = cv2.flip(frame, 1)
            
            # Détection de visage en temps réel
            rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            face_locations = face_recognition.face_locations(rgb_frame, model="hog")
            
            # Dessiner les rectangles autour des visages détectés
            display_frame = frame.copy()
            for (top, right, bottom, left) in face_locations:
                cv2.rectangle(display_frame, (left, top), (right, bottom), (0, 255, 0), 2)
            
            # Afficher le compteur
            cv2.putText(display_frame, f"Captures: {captured_count}/{self.capture_count}", 
                       (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)
            
            if face_locations:
                cv2.putText(display_frame, "Visage detecte - ESPACE pour capturer", 
                           (10, 70), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)
            else:
                cv2.putText(display_frame, "Aucun visage detecte", 
                           (10, 70), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2)
            
            cv2.imshow("Capture Faciale - BioID", display_frame)
            
            key = cv2.waitKey(1) & 0xFF
            
            # ESPACE pour capturer
            if key == ord(' ') and face_locations:
                # Extraire l'encodage facial
                encodings = face_recognition.face_encodings(rgb_frame, face_locations)
                
                if encodings:
                    self.captures.append(frame.copy())
                    self.encodings.append(encodings[0])
                    captured_count += 1
                    print(f"[OK] Capture {captured_count}/{self.capture_count} effectuée")
                    
                    # Flash visuel
                    cv2.imshow("Capture Faciale - BioID", np.ones_like(frame) * 255)
                    cv2.waitKey(100)
            
            # Q pour quitter
            elif key == ord('q'):
                print("[INFO] Capture annulée par l'utilisateur")
                break
        
        cap.release()
        cv2.destroyAllWindows()
        
        return self.encodings
    
    def get_average_encoding(self):
        """
        Calcule l'encodage moyen à partir des captures multiples
        
        Returns:
            numpy.ndarray: Encodage facial moyen (128 dimensions)
        """
        if not self.encodings:
            return None
        
        return np.mean(self.encodings, axis=0)
    
    def save_captures(self, save_dir, beneficiary_id):
        """
        Sauvegarde les captures dans un dossier
        
        Args:
            save_dir: Dossier de destination
            beneficiary_id: ID du bénéficiaire
        """
        person_dir = os.path.join(save_dir, beneficiary_id)
        os.makedirs(person_dir, exist_ok=True)
        
        for i, capture in enumerate(self.captures):
            filename = f"face_{i+1}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg"
            filepath = os.path.join(person_dir, filename)
            cv2.imwrite(filepath, capture)
            print(f"[OK] Sauvegardé: {filepath}")
        
        return person_dir


def compare_faces(known_encoding, unknown_encoding, tolerance=0.6):
    """
    Compare deux encodages faciaux
    
    Args:
        known_encoding: Encodage enregistré
        unknown_encoding: Encodage à vérifier
        tolerance: Seuil de tolérance (plus bas = plus strict)
        
    Returns:
        tuple: (match: bool, distance: float)
    """
    if known_encoding is None or unknown_encoding is None:
        return False, 1.0
    
    distance = np.linalg.norm(known_encoding - unknown_encoding)
    match = distance <= tolerance
    
    return match, distance


# Test du module
if __name__ == "__main__":
    print("=== Test du module de capture faciale ===")
    
    face_capture = FaceCapture(capture_count=3)
    encodings = face_capture.start_capture()
    
    if encodings:
        avg_encoding = face_capture.get_average_encoding()
        print(f"\n[OK] {len(encodings)} captures effectuées")
        print(f"[OK] Dimension de l'encodage moyen: {avg_encoding.shape}")
        print(f"[OK] Premiers valeurs: {avg_encoding[:5]}")
    else:
        print("[ERREUR] Aucune capture effectuée")
