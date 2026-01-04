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
from typing import Dict, List, Tuple

# Use project data directory when available (works with Docker mounts)
try:
    from config import DATA_DIR
except Exception:
    DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")


class BiometricMetrics:
    """Calcul et analyse des métriques biométriques"""
    
    def __init__(self, results_file=None):
        """
        Args:
            results_file: Fichier de stockage des résultats
        """
        # Default to project's data directory so metrics read Docker-mounted data
        if results_file is None:
            results_file = os.path.join(DATA_DIR, "metrics", "verification_results.json")

        self.results_file = results_file
        self.results = self._load_results()
    
    def _load_results(self):
        """Charge les résultats de vérification"""
        os.makedirs(os.path.dirname(self.results_file), exist_ok=True)

        print("[METRICS] 🔄 Always reloading from audit logs to ensure fresh data...")
        
        # Always try to ingest from audit logs first (Source of Truth)
        ingested = self._ingest_from_audit_logs()
        
        if ingested:
            # Save newly calculated results
            self._save_results()
            return self.results
            
        print("[METRICS] ⚠️ No audit log data found. Checking for cached metrics...")

        # Fallback: Load existing file if audit logs didn't yield anything
        if os.path.exists(self.results_file):
            try:
                with open(self.results_file, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, dict) and ("genuine" in data or "impostor" in data):
                        print(f"[METRICS] Loaded cached metrics from {self.results_file}")
                        return data
            except Exception as e:
                print(f"[METRICS] Error loading existing file: {e}")

        # Fallback: empty structure
        print("[METRICS] Warning: No data found anywhere. Returning empty metrics.")
        return {"genuine": [], "impostor": []}

    def _ingest_from_audit_logs(self) -> bool:
        """Ingest verification events from audit logs to populate metrics.

        This scans the project's `data/audit` directory for JSON files containing
        verification events. It converts event confidences to a score between 0-1
        compatible with FAR/FRR methods (lower score = better match).
        """
        audit_dir = os.path.join(DATA_DIR, "audit")
        print(f"[METRICS] Scanning audit directory: {audit_dir}")
        
        if not os.path.isdir(audit_dir):
            print(f"[METRICS] Audit directory not found: {audit_dir}")
            return False

        any_found = False
        # ensure results structure
        self.results = {"genuine": [], "impostor": []}
        
        files = sorted([f for f in os.listdir(audit_dir) if f.endswith('.json')])
        if not files:
            print("[METRICS] No JSON log files found in audit directory.")
            return False

        print(f"[METRICS] Found {len(files)} log files: {files}")

        for fname in files:
            print(f"[METRICS] Processing file: {fname}")
            path = os.path.join(audit_dir, fname)
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    content = json.load(f)
            except Exception as e:
                print(f"[METRICS] Error reading {fname}: {e}")
                continue

            logs = content.get('logs') if isinstance(content, dict) else content
            if not logs:
                print(f"[METRICS] No logs found in {fname}")
                continue

            for event in logs:
                try:
                    if event.get('event_type') != 'verification':
                        continue

                    timestamp = event.get('timestamp') or datetime.now().isoformat()
                    success = event.get('success', False)
                    details = event.get('details', {}) or {}
                    confidence = details.get('confidence') or {}
                    bio_id = event.get('bio_id', 'unknown')

                    print(f"[METRICS] Use event: {timestamp} | BioID: {bio_id} | Success: {success} | Raw Confidence: {confidence}")

                    # confidence is expected to be a dict like {"face": 78.7, "fingerprint": 94.6}
                    if isinstance(confidence, dict):
                        for modality, val in confidence.items():
                            # convert value to numeric score where lower is better
                            try:
                                num = float(val)
                            except Exception:
                                continue

                            # Heuristics:
                            # - If confidence > 1, treat as percentage (0-100)
                            #   convert to normalized confidence [0,1] then to distance-like score
                            # - If confidence already in [0,1], treat as similarity and convert
                            if num > 1:
                                normalized = num / 100.0
                                score = max(0.0, min(1.0, 1.0 - normalized))
                            else:
                                # assume similarity where higher is better -> convert
                                score = max(0.0, min(1.0, 1.0 - num))

                            record = {
                                "score": float(score),
                                "modality": modality,
                                "timestamp": timestamp
                            }
                            
                            print(f"  -> Ingested {modality}: score={score:.4f} (derived from {num})")

                            if success:
                                self.results['genuine'].append(record)
                            else:
                                self.results['impostor'].append(record)

                            any_found = True
                    else:
                        print(f"  -> Skipped: Confidence is not a dict: {type(confidence)}")

                except Exception as e:
                    print(f"[METRICS] Error processing event: {e}")
                    continue

        if any_found:
            print(f"[METRICS] Successfully ingested {len(self.results['genuine'])} genuine and {len(self.results['impostor'])} impostor records.")
        else:
            print("[METRICS] No verification events found in logs.")
            
        return any_found
    
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
        Reloads data source each time to ensure real-time updates.
        
        Returns:
            dict: Rapport complet
        """
        # RELOAD DATA to ensure fresh metrics
        self.results = self._load_results()
        
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

    def analyze_demographic_bias(self, demographic_data: Dict) -> Dict:
        """
        Analyse les biais démographiques dans les performances

        Args:
            demographic_data: Données démographiques structurées

        Returns:
            Dict: Analyse détaillée des biais
        """
        bias_analysis = {
            "analysis_date": datetime.now().isoformat(),
            "demographic_groups": {},
            "fairness_metrics": {},
            "bias_indicators": [],
            "recommendations": []
        }

        # Analyser chaque dimension démographique
        for dimension, groups in demographic_data.items():
            group_analysis = {}

            for group_name, scores in groups.items():
                if not scores:
                    continue

                scores_array = np.array(scores)
                genuine_scores = scores_array[scores_array < 0.5]
                impostor_scores = scores_array[scores_array >= 0.5]

                group_analysis[group_name] = {
                    "sample_size": len(scores),
                    "mean_score": float(np.mean(scores_array)),
                    "std_score": float(np.std(scores_array)),
                    "genuine_rate": len(genuine_scores) / len(scores_array) if scores_array.size > 0 else 0,
                    "accuracy": self._calculate_group_accuracy(scores_array)
                }

            bias_analysis["demographic_groups"][dimension] = group_analysis

            # Calculer les métriques de biais pour cette dimension
            if len(group_analysis) >= 2:
                bias_metrics = self._calculate_bias_metrics(group_analysis)
                bias_analysis["fairness_metrics"][dimension] = bias_metrics

                # Détecter les biais significatifs
                for metric_name, metric_value in bias_metrics.items():
                    if abs(metric_value) > 0.05:
                        bias_analysis["bias_indicators"].append({
                            "dimension": dimension,
                            "metric": metric_name,
                            "value": metric_value,
                            "severity": "high" if abs(metric_value) > 0.1 else "medium",
                            "description": f"Biais détecté dans {dimension} ({metric_name}: {metric_value:.3f})"
                        })

        # Générer des recommandations
        if bias_analysis["bias_indicators"]:
            bias_analysis["recommendations"].extend([
                "Diversify training dataset to reduce demographic bias",
                "Implement fairness-aware algorithms",
                "Regular bias monitoring and reporting",
                "Consider alternative verification methods for biased groups"
            ])

        return bias_analysis

    def _calculate_group_accuracy(self, scores: np.ndarray) -> float:
        """Calcule la précision pour un groupe démographique"""
        estimated_accuracy = np.mean(scores < 0.5)
        return float(estimated_accuracy)

    def _calculate_bias_metrics(self, group_analysis: Dict) -> Dict:
        """Calcule les métriques de biais entre groupes"""
        metrics = {}

        if len(group_analysis) < 2:
            return metrics

        accuracies = {group: data["accuracy"] for group, data in group_analysis.items()}
        acc_values = list(accuracies.values())
        mean_accuracy = np.mean(acc_values)
        
        metrics["mean_absolute_bias"] = float(np.mean([abs(acc - mean_accuracy) for acc in acc_values]))
        metrics["max_bias"] = float(max(acc_values) - min(acc_values))

        if max(acc_values) > 0:
            metrics["accuracy_ratio"] = float(min(acc_values) / max(acc_values))

        metrics["normalized_disparity"] = float((max(acc_values) - min(acc_values)) / mean_accuracy) if mean_accuracy > 0 else 0

        return metrics

    def analyze_fairness_constraints(self, threshold: float, demographic_data: Dict) -> Dict:
        """Analyse les contraintes d'équité pour un seuil donné"""
        fairness_analysis = {
            "threshold": threshold,
            "group_fairness": {},
            "overall_fairness_score": 0,
            "fairness_violations": []
        }

        for dimension, groups in demographic_data.items():
            group_fairness = {}

            for group_name, scores in groups.items():
                if not scores:
                    continue

                scores_array = np.array(scores)
                far, frr = self._calculate_group_far_frr(scores_array, threshold)

                group_fairness[group_name] = {
                    "far": far,
                    "frr": frr,
                    "sample_size": len(scores),
                    "fairness_score": 1 - abs(far - frr)
                }

            fairness_analysis["group_fairness"][dimension] = group_fairness

            fairness_scores = [data["fairness_score"] for data in group_fairness.values()]
            if fairness_scores:
                min_fairness = min(fairness_scores)
                max_fairness = max(fairness_scores)
                disparity = max_fairness - min_fairness

                if disparity > 0.2:
                    fairness_analysis["fairness_violations"].append({
                        "dimension": dimension,
                        "disparity": disparity,
                        "description": f"Équité compromise dans {dimension} (disparité: {disparity:.3f})"
                    })

        all_fairness_scores = []
        for dimension_data in fairness_analysis["group_fairness"].values():
            all_fairness_scores.extend([data["fairness_score"] for data in dimension_data.values()])

        if all_fairness_scores:
            fairness_analysis["overall_fairness_score"] = float(np.mean(all_fairness_scores))

        return fairness_analysis

    def _calculate_group_far_frr(self, scores: np.ndarray, threshold: float) -> Tuple[float, float]:
        """Calcule FAR et FRR pour un groupe spécifique"""
        genuine_scores = scores[scores < threshold]
        impostor_scores = scores[scores >= threshold]

        far = len(impostor_scores) / len(scores) if len(scores) > 0 else 0
        frr = len(genuine_scores) / len(scores) if len(scores) > 0 else 0

        return float(far), float(frr)

    def generate_bias_report(self, demographic_data: Dict = None) -> Dict:
        """Génère un rapport complet sur les biais et l'équité"""
        report = {
            "report_date": datetime.now().isoformat(),
            "bias_analysis": {},
            "fairness_analysis": {},
            "system_limitations": [],
            "recommendations": []
        }

        if demographic_data:
            report["bias_analysis"] = self.analyze_demographic_bias(demographic_data)

            eer, optimal_threshold = self.calculate_eer()
            if optimal_threshold:
                report["fairness_analysis"] = self.analyze_fairness_constraints(
                    optimal_threshold, demographic_data
                )

        limitations = self._identify_system_limitations()
        report["system_limitations"] = limitations

        recommendations = self._generate_bias_recommendations(report)
        report["recommendations"] = recommendations

        return report

    def _identify_system_limitations(self) -> List[Dict]:
        """Identifie les limitations du système biométrique"""
        limitations = []

        genuine_count = len(self.results["genuine"])
        impostor_count = len(self.results["impostor"])

        if genuine_count < 1000:
            limitations.append({
                "type": "sample_size",
                "severity": "high",
                "description": f"Échantillon de tests légitimes insuffisant ({genuine_count}). Minimum recommandé: 1000",
                "impact": "Réduction de la fiabilité des métriques"
            })

        if impostor_count < 1000:
            limitations.append({
                "type": "sample_size",
                "severity": "high",
                "description": f"Échantillon de tests imposteurs insuffisant ({impostor_count}). Minimum recommandé: 1000",
                "impact": "Estimation FAR imprécise"
            })

        modalities = set()
        for result in self.results["genuine"] + self.results["impostor"]:
            modalities.add(result["modality"])

        if len(modalities) < 2:
            limitations.append({
                "type": "modality_diversity",
                "severity": "medium",
                "description": "Tests limités à une seule modalité biométrique",
                "impact": "Impossible d'évaluer la fusion multimodale"
            })

        if self.results["genuine"]:
            timestamps = [r["timestamp"] for r in self.results["genuine"]]
            dates = [ts.split("T")[0] for ts in timestamps]
            unique_dates = len(set(dates))

            if unique_dates < 7:
                limitations.append({
                    "type": "temporal_robustness",
                    "severity": "low",
                    "description": f"Tests sur seulement {unique_dates} jours. Recommandé: au moins 7 jours",
                    "impact": "Robustesse temporelle non validée"
                })

        return limitations

    def _generate_bias_recommendations(self, bias_report: Dict) -> List[str]:
        """Génère des recommandations basées sur l'analyse des biais"""
        recommendations = []

        if "bias_analysis" in bias_report and bias_report["bias_analysis"].get("bias_indicators"):
            bias_indicators = bias_report["bias_analysis"]["bias_indicators"]
            severe_biases = [b for b in bias_indicators if b["severity"] == "high"]

            if severe_biases:
                recommendations.extend([
                    "URGENT: Corriger les biais démographiques critiques avant déploiement",
                    "Augmenter la diversité des données d'entraînement",
                    "Implémenter des algorithmes d'équité (fairness-aware)"
                ])
            else:
                recommendations.extend([
                    "Surveiller l'évolution des biais démographiques",
                    "Planifier des audits réguliers d'équité"
                ])

        if "system_limitations" in bias_report:
            limitations = bias_report["system_limitations"]
            high_severity = [l for l in limitations if l["severity"] == "high"]

            if high_severity:
                recommendations.extend([
                    "Augmenter la taille des jeux de test",
                    "Diversifier les scénarios de test",
                    "Valider sur des données réelles avant déploiement"
                ])

        recommendations.extend([
            "Établir un comité d'éthique pour la surveillance continue",
            "Documenter et communiquer la transparence algorithmique",
            "Fournir des alternatives non-biométriques pour les groupes défavorisés",
            "Mettre en place un mécanisme de plainte pour les erreurs de reconnaissance"
        ])

        return list(set(recommendations))

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