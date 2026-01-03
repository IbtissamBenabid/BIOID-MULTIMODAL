"""
Module de métriques biométriques
Calcul FAR, FRR, EER et analyse des performances
"""
import numpy as np
from scipy.optimize import brentq
from scipy.interpolate import interp1d
import json
import os
from datetime import datetime


class BiometricMetrics:
    """Calcul et analyse des métriques biométriques"""
    
    def __init__(self, results_file="data/metrics/verification_results.json"):
        """
        Args:
            results_file: Fichier de stockage des résultats
        """
        self.results_file = results_file
        self.results = self._load_results()
    
    def _load_results(self):
        """Charge les résultats de vérification"""
        os.makedirs(os.path.dirname(self.results_file), exist_ok=True)
        
        if os.path.exists(self.results_file):
            with open(self.results_file, 'r') as f:
                return json.load(f)
        return {"genuine": [], "impostor": []}
    
    def _save_results(self):
        """Sauvegarde les résultats"""
        with open(self.results_file, 'w') as f:
            json.dump(self.results, f, indent=2)
    
    def record_verification(self, is_genuine, score, modality="face"):
        """
        Enregistre un résultat de vérification pour analyse
        
        Args:
            is_genuine: True si même personne, False si imposteur
            score: Score de similarité/distance
            modality: Type de biométrie (face, fingerprint, voice)
        """
        result = {
            "score": float(score),
            "modality": modality,
            "timestamp": datetime.now().isoformat()
        }
        
        if is_genuine:
            self.results["genuine"].append(result)
        else:
            self.results["impostor"].append(result)
        
        self._save_results()
    
    def calculate_far_frr(self, threshold, modality=None):
        """
        Calcule FAR et FRR pour un seuil donné
        
        FAR (False Acceptance Rate): % imposteurs acceptés
        FRR (False Rejection Rate): % légitimes rejetés
        
        Args:
            threshold: Seuil de décision
            modality: Filtrer par modalité (optionnel)
            
        Returns:
            tuple: (FAR, FRR)
        """
        genuine = self.results["genuine"]
        impostor = self.results["impostor"]
        
        # Filtrer par modalité si spécifié
        if modality:
            genuine = [r for r in genuine if r["modality"] == modality]
            impostor = [r for r in impostor if r["modality"] == modality]
        
        if not genuine or not impostor:
            return 0.0, 0.0
        
        genuine_scores = [r["score"] for r in genuine]
        impostor_scores = [r["score"] for r in impostor]
        
        # Pour les distances (plus bas = meilleur match)
        # FAR: imposteurs avec score <= threshold (faussement acceptés)
        # FRR: légitimes avec score > threshold (faussement rejetés)
        
        far = sum(1 for s in impostor_scores if s <= threshold) / len(impostor_scores)
        frr = sum(1 for s in genuine_scores if s > threshold) / len(genuine_scores)
        
        return far * 100, frr * 100
    
    def calculate_eer(self, modality=None):
        """
        Calcule l'EER (Equal Error Rate)
        Point où FAR = FRR
        
        Args:
            modality: Filtrer par modalité (optionnel)
            
        Returns:
            tuple: (EER, threshold_optimal)
        """
        genuine = self.results["genuine"]
        impostor = self.results["impostor"]
        
        if modality:
            genuine = [r for r in genuine if r["modality"] == modality]
            impostor = [r for r in impostor if r["modality"] == modality]
        
        if not genuine or not impostor:
            return None, None
        
        genuine_scores = np.array([r["score"] for r in genuine])
        impostor_scores = np.array([r["score"] for r in impostor])
        
        # Générer des seuils à tester
        all_scores = np.concatenate([genuine_scores, impostor_scores])
        thresholds = np.linspace(all_scores.min(), all_scores.max(), 100)
        
        fars = []
        frrs = []
        
        for t in thresholds:
            far = np.mean(impostor_scores <= t) * 100
            frr = np.mean(genuine_scores > t) * 100
            fars.append(far)
            frrs.append(frr)
        
        fars = np.array(fars)
        frrs = np.array(frrs)
        
        # Trouver le point où FAR ≈ FRR
        try:
            # Interpolation pour trouver l'intersection
            diff = fars - frrs
            idx = np.argmin(np.abs(diff))
            eer = (fars[idx] + frrs[idx]) / 2
            threshold_optimal = thresholds[idx]
            
            return eer, threshold_optimal
        except:
            return None, None
    
    def analyze_thresholds(self, modality=None):
        """
        Analyse des seuils et recommandations
        
        Args:
            modality: Filtrer par modalité
            
        Returns:
            dict: Analyse complète
        """
        genuine = self.results["genuine"]
        impostor = self.results["impostor"]
        
        if modality:
            genuine = [r for r in genuine if r["modality"] == modality]
            impostor = [r for r in impostor if r["modality"] == modality]
        
        if not genuine or not impostor:
            return {"error": "Données insuffisantes"}
        
        genuine_scores = np.array([r["score"] for r in genuine])
        impostor_scores = np.array([r["score"] for r in impostor])
        
        eer, eer_threshold = self.calculate_eer(modality)
        
        analysis = {
            "modality": modality or "all",
            "sample_size": {
                "genuine": len(genuine),
                "impostor": len(impostor)
            },
            "genuine_stats": {
                "mean": float(np.mean(genuine_scores)),
                "std": float(np.std(genuine_scores)),
                "min": float(np.min(genuine_scores)),
                "max": float(np.max(genuine_scores)),
                "median": float(np.median(genuine_scores))
            },
            "impostor_stats": {
                "mean": float(np.mean(impostor_scores)),
                "std": float(np.std(impostor_scores)),
                "min": float(np.min(impostor_scores)),
                "max": float(np.max(impostor_scores)),
                "median": float(np.median(impostor_scores))
            },
            "eer": eer,
            "eer_threshold": eer_threshold,
            "thresholds_analysis": []
        }
        
        # Analyser différents seuils
        for threshold in [0.3, 0.4, 0.5, 0.6, 0.7]:
            far, frr = self.calculate_far_frr(threshold, modality)
            analysis["thresholds_analysis"].append({
                "threshold": threshold,
                "far": far,
                "frr": frr,
                "security_level": "high" if far < 1 else "medium" if far < 5 else "low"
            })
        
        # Recommandation
        if eer is not None:
            if eer < 1:
                analysis["recommendation"] = f"Excellent système (EER={eer:.2f}%). Seuil recommandé: {eer_threshold:.3f}"
            elif eer < 5:
                analysis["recommendation"] = f"Bon système (EER={eer:.2f}%). Seuil recommandé: {eer_threshold:.3f}"
            else:
                analysis["recommendation"] = f"Système à améliorer (EER={eer:.2f}%). Considérez la fusion multimodale."
        
        return analysis
    
    def generate_report(self):
        """
        Génère un rapport complet des métriques
        
        Returns:
            dict: Rapport complet
        """
        report = {
            "generated_at": datetime.now().isoformat(),
            "overall": self.analyze_thresholds(),
            "by_modality": {}
        }
        
        # Analyse par modalité
        modalities = set()
        for r in self.results["genuine"] + self.results["impostor"]:
            modalities.add(r["modality"])
        
        for modality in modalities:
            report["by_modality"][modality] = self.analyze_thresholds(modality)
        
        # Risques et biais
        report["risks"] = self._analyze_risks()
        
        return report
    
    def _analyze_risks(self):
        """Analyse des risques du système"""
        risks = []
        
        genuine_count = len(self.results["genuine"])
        impostor_count = len(self.results["impostor"])
        
        if genuine_count < 100:
            risks.append({
                "type": "sample_size",
                "severity": "high",
                "description": f"Échantillon insuffisant ({genuine_count} tests légitimes). Minimum recommandé: 100"
            })
        
        if impostor_count < 100:
            risks.append({
                "type": "sample_size",
                "severity": "high",
                "description": f"Échantillon imposteurs insuffisant ({impostor_count}). Minimum recommandé: 100"
            })
        
        eer, _ = self.calculate_eer()
        if eer and eer > 5:
            risks.append({
                "type": "accuracy",
                "severity": "medium",
                "description": f"EER élevé ({eer:.2f}%). Risque d'erreurs d'authentification"
            })
        
        # Biais potentiels
        risks.append({
            "type": "bias",
            "severity": "info",
            "description": "Vérifier la diversité des données de test (âge, genre, ethnie) pour détecter les biais"
        })
        
        return risks
    
    def clear_results(self):
        """Efface les résultats (pour tests)"""
        self.results = {"genuine": [], "impostor": []}
        self._save_results()


# Simulateur pour tests
def simulate_verification_data(metrics, n_genuine=100, n_impostor=100):
    """
    Simule des données de vérification pour tests
    
    Args:
        metrics: Instance BiometricMetrics
        n_genuine: Nombre de tests légitimes
        n_impostor: Nombre de tests imposteurs
    """
    # Scores légitimes (distances faibles)
    genuine_scores = np.random.normal(0.25, 0.1, n_genuine)
    genuine_scores = np.clip(genuine_scores, 0, 1)
    
    # Scores imposteurs (distances élevées)
    impostor_scores = np.random.normal(0.7, 0.15, n_impostor)
    impostor_scores = np.clip(impostor_scores, 0, 1)
    
    for score in genuine_scores:
        metrics.record_verification(True, score, "face")
    
    for score in impostor_scores:
        metrics.record_verification(False, score, "face")
    
    print(f"[OK] Simulé {n_genuine} tests légitimes et {n_impostor} tests imposteurs")


# Test du module
if __name__ == "__main__":
    print("=== Test du module de métriques ===")
    
    metrics = BiometricMetrics()
    metrics.clear_results()
    
    # Simuler des données
    simulate_verification_data(metrics, 100, 100)
    
    # Calculer les métriques
    far, frr = metrics.calculate_far_frr(0.5)
    print(f"\n[OK] Seuil 0.5: FAR={far:.2f}%, FRR={frr:.2f}%")
    
    eer, threshold = metrics.calculate_eer()
    print(f"[OK] EER={eer:.2f}% au seuil {threshold:.3f}")
    
    # Analyse complète
    analysis = metrics.analyze_thresholds()
    print(f"\n[OK] Analyse: {json.dumps(analysis, indent=2)}")
