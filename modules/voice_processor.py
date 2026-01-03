"""
Module de traitement vocal
Capture et extraction des caractéristiques vocales (MFCC)
"""
import numpy as np
import os
from datetime import datetime

try:
    import librosa
    import sounddevice as sd
    import scipy.io.wavfile as wav
    VOICE_AVAILABLE = True
except ImportError:
    VOICE_AVAILABLE = False
    print("[WARNING] Modules audio non installés. Installez: pip install librosa sounddevice scipy")


class VoiceProcessor:
    """Gère le traitement et l'extraction des caractéristiques vocales"""
    
    def __init__(self, sample_rate=16000, duration=3):
        """
        Args:
            sample_rate: Fréquence d'échantillonnage (Hz)
            duration: Durée d'enregistrement (secondes)
        """
        self.sample_rate = sample_rate
        self.duration = duration
        self.audio_data = None
        self.features = None
        
    def record_voice(self):
        """
        Enregistre la voix via le microphone
        
        Returns:
            numpy.ndarray: Signal audio enregistré
        """
        if not VOICE_AVAILABLE:
            raise RuntimeError("Modules audio non disponibles")
        
        print(f"[INFO] Enregistrement pendant {self.duration} secondes...")
        
        self.audio_data = sd.rec(
            int(self.duration * self.sample_rate),
            samplerate=self.sample_rate,
            channels=1,
            dtype='float32'
        )
        sd.wait()
        
        self.audio_data = self.audio_data.flatten()
        print("[OK] Enregistrement terminé")
        
        return self.audio_data
    
    def load_audio(self, filepath):
        """
        Charge un fichier audio
        
        Args:
            filepath: Chemin vers le fichier audio
        """
        if not VOICE_AVAILABLE:
            raise RuntimeError("Modules audio non disponibles")
        
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Fichier non trouvé: {filepath}")
        
        self.audio_data, sr = librosa.load(filepath, sr=self.sample_rate)
        print(f"[OK] Audio chargé: {len(self.audio_data)} échantillons")
        
        return self.audio_data
    
    def load_from_bytes(self, audio_bytes):
        """
        Charge un audio depuis des bytes (pour upload web)
        
        Args:
            audio_bytes: Bytes du fichier audio
        """
        if not VOICE_AVAILABLE:
            raise RuntimeError("Modules audio non disponibles")
        
        import tempfile
        
        # Sauvegarder temporairement pour librosa
        tmp_path = tempfile.mktemp(suffix='.wav')
        
        try:
            with open(tmp_path, 'wb') as tmp:
                tmp.write(audio_bytes)
            
            self.audio_data, sr = librosa.load(tmp_path, sr=self.sample_rate)
        finally:
            # Supprimer le fichier temporaire après fermeture
            try:
                os.unlink(tmp_path)
            except:
                pass
        
        return self.audio_data
    
    def preprocess(self):
        """
        Prétraitement du signal audio
        - Normalisation
        - Suppression du silence
        - Pré-emphase
        """
        if self.audio_data is None:
            raise ValueError("Aucun audio chargé")
        
        # Normalisation
        audio = self.audio_data / (np.max(np.abs(self.audio_data)) + 1e-7)
        
        # Suppression des silences (basique)
        threshold = 0.01
        non_silent = np.abs(audio) > threshold
        if np.any(non_silent):
            # Trouver le début et la fin du signal non-silencieux
            indices = np.where(non_silent)[0]
            start, end = indices[0], indices[-1]
            audio = audio[start:end+1]
        
        # Pré-emphase (améliore les hautes fréquences)
        pre_emphasis = 0.97
        audio = np.append(audio[0], audio[1:] - pre_emphasis * audio[:-1])
        
        self.audio_data = audio
        print("[OK] Prétraitement audio terminé")
        
        return audio
    
    def extract_features(self):
        """
        Extrait les caractéristiques MFCC (Mel-Frequency Cepstral Coefficients)
        
        Returns:
            numpy.ndarray: Vecteur de caractéristiques vocales
        """
        if not VOICE_AVAILABLE:
            raise RuntimeError("Modules audio non disponibles")
        
        if self.audio_data is None:
            raise ValueError("Aucun audio chargé")
        
        # Extraire les MFCC
        mfccs = librosa.feature.mfcc(
            y=self.audio_data,
            sr=self.sample_rate,
            n_mfcc=20,  # 20 coefficients
            n_fft=512,
            hop_length=256
        )
        
        # Calculer les statistiques des MFCC
        features = []
        
        # Moyenne et écart-type de chaque coefficient
        features.extend(np.mean(mfccs, axis=1))
        features.extend(np.std(mfccs, axis=1))
        
        # Delta MFCC (dérivée première)
        delta_mfccs = librosa.feature.delta(mfccs)
        features.extend(np.mean(delta_mfccs, axis=1))
        features.extend(np.std(delta_mfccs, axis=1))
        
        # Delta-delta MFCC (dérivée seconde)
        delta2_mfccs = librosa.feature.delta(mfccs, order=2)
        features.extend(np.mean(delta2_mfccs, axis=1))
        features.extend(np.std(delta2_mfccs, axis=1))
        
        # Énergie moyenne
        rms = librosa.feature.rms(y=self.audio_data)
        features.append(np.mean(rms))
        features.append(np.std(rms))
        
        # Zero-crossing rate
        zcr = librosa.feature.zero_crossing_rate(self.audio_data)
        features.append(np.mean(zcr))
        features.append(np.std(zcr))
        
        self.features = np.array(features, dtype=np.float32)
        
        # Normaliser
        norm = np.linalg.norm(self.features)
        if norm > 0:
            self.features = self.features / norm
        
        print(f"[OK] Vecteur vocal extrait: {len(self.features)} dimensions")
        return self.features
    
    def save_audio(self, save_dir, beneficiary_id):
        """
        Sauvegarde l'enregistrement audio
        
        Args:
            save_dir: Dossier de destination
            beneficiary_id: ID du bénéficiaire
        """
        if self.audio_data is None:
            return None
        
        os.makedirs(save_dir, exist_ok=True)
        filename = f"voice_{beneficiary_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.wav"
        filepath = os.path.join(save_dir, filename)
        
        wav.write(filepath, self.sample_rate, (self.audio_data * 32767).astype(np.int16))
        print(f"[OK] Audio sauvegardé: {filepath}")
        
        return filepath


def compare_voices(features1, features2, threshold=0.3):
    """
    Compare deux empreintes vocales
    
    Args:
        features1: Vecteur de caractéristiques 1
        features2: Vecteur de caractéristiques 2
        threshold: Seuil de distance (plus bas = plus strict)
        
    Returns:
        tuple: (match: bool, distance: float)
    """
    if features1 is None or features2 is None:
        return False, 1.0
    
    # Distance euclidienne
    distance = np.linalg.norm(np.array(features1) - np.array(features2))
    match = distance <= threshold
    
    return match, float(distance)


# Test du module
if __name__ == "__main__":
    print("=== Test du module vocal ===")
    
    if VOICE_AVAILABLE:
        processor = VoiceProcessor(duration=3)
        
        print("Parlez après le bip...")
        processor.record_voice()
        processor.preprocess()
        features = processor.extract_features()
        
        print(f"\n[OK] Extraction terminée")
        print(f"[OK] Dimension du vecteur: {len(features)}")
    else:
        print("[INFO] Installez les dépendances: pip install librosa sounddevice scipy")
