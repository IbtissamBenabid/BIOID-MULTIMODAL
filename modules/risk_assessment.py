"""
Module d'analyse des risques biométriques
Évaluation des menaces, vulnérabilités et mesures de mitigation
"""
import json
import os
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Tuple
import numpy as np


class AttackType(Enum):
    """Types d'attaques biométriques"""
    SPOOFING = "spoofing"
    REPLAY_ATTACK = "replay_attack"
    TEMPLATE_ATTACK = "template_attack"
    HILL_CLIMBING = "hill_climbing"
    BIOMETRIC_SYNTHESIS = "biometric_synthesis"
    PRESENTATION_ATTACK = "presentation_attack"
    INVERSION_ATTACK = "inversion_attack"


class RiskLevel(Enum):
    """Niveaux de risque"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskAssessment:
    """Évaluation des risques du système biométrique"""

    def __init__(self, data_dir="data/risk_assessment"):
        """
        Args:
            data_dir: Répertoire de stockage des données d'évaluation
        """
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)

        self.assessment_file = os.path.join(data_dir, "risk_assessments.json")
        self.threat_model_file = os.path.join(data_dir, "threat_model.json")

        self._init_risk_data()

    def _init_risk_data(self):
        """Initialise les données d'évaluation des risques"""
        if not os.path.exists(self.assessment_file):
            with open(self.assessment_file, 'w') as f:
                json.dump({"assessments": []}, f, indent=2)

        if not os.path.exists(self.threat_model_file):
            threat_model = self._generate_threat_model()
            with open(self.threat_model_file, 'w') as f:
                json.dump(threat_model, f, indent=2)

    def _generate_threat_model(self) -> Dict:
        """Génère le modèle de menaces pour le système biométrique"""
        return {
            "system_components": [
                "Webcam capture",
                "Fingerprint scanner",
                "Microphone input",
                "Face recognition engine",
                "Fingerprint processor",
                "Voice analyzer",
                "Database storage",
                "API endpoints",
                "Frontend interface"
            ],
            "threat_actors": [
                {
                    "actor": "Malicious beneficiary",
                    "motivation": "Fraudulent aid collection",
                    "capabilities": "Basic spoofing attempts",
                    "likelihood": "high"
                },
                {
                    "actor": "Organized crime",
                    "motivation": "Large-scale fraud",
                    "capabilities": "Advanced spoofing, template attacks",
                    "likelihood": "medium"
                },
                {
                    "actor": "Insider threat",
                    "motivation": "Data theft, sabotage",
                    "capabilities": "System access, database manipulation",
                    "likelihood": "low"
                },
                {
                    "actor": "State actor",
                    "motivation": "Surveillance, data collection",
                    "capabilities": "Advanced attacks, supply chain compromise",
                    "likelihood": "low"
                }
            ],
            "attack_vectors": {
                "face_spoofing": {
                    "description": "Photo/video replay, 3D masks, makeup",
                    "detected_by": ["Liveness detection", "Multi-angle capture"],
                    "mitigation_level": "medium"
                },
                "fingerprint_spoofing": {
                    "description": "Gelatin fingerprints, lifted prints",
                    "detected_by": ["Pore analysis", "Temperature sensing"],
                    "mitigation_level": "high"
                },
                "voice_spoofing": {
                    "description": "Audio replay, voice synthesis",
                    "detected_by": ["Liveness detection", "Multi-factor verification"],
                    "mitigation_level": "medium"
                },
                "template_attack": {
                    "description": "Stolen encrypted templates",
                    "detected_by": ["Template encryption", "Regular rotation"],
                    "mitigation_level": "high"
                },
                "database_attack": {
                    "description": "SQL injection, data breach",
                    "detected_by": ["Input validation", "Encryption at rest"],
                    "mitigation_level": "high"
                }
            }
        }

    def assess_attack_vulnerability(self, attack_type: AttackType,
                                 system_configuration: Dict) -> Dict:
        """
        Évalue la vulnérabilité à un type d'attaque spécifique

        Args:
            attack_type: Type d'attaque
            system_configuration: Configuration du système

        Returns:
            Dict: Évaluation de vulnérabilité
        """
        base_vulnerabilities = {
            AttackType.SPOOFING: {
                "face": {"base_risk": "high", "current_mitigations": ["multi_capture", "quality_check"]},
                "fingerprint": {"base_risk": "medium", "current_mitigations": ["quality_validation"]},
                "voice": {"base_risk": "high", "current_mitigations": ["liveness_check"]}
            },
            AttackType.REPLAY_ATTACK: {
                "face": {"base_risk": "high", "current_mitigations": ["motion_detection"]},
                "fingerprint": {"base_risk": "low", "current_mitigations": ["live_scan"]},
                "voice": {"base_risk": "high", "current_mitigations": ["real_time_check"]}
            },
            AttackType.TEMPLATE_ATTACK: {
                "all": {"base_risk": "medium", "current_mitigations": ["encryption", "access_control"]}
            }
        }

        assessment = {
            "attack_type": attack_type.value,
            "assessment_date": datetime.now().isoformat(),
            "modalities": {},
            "overall_risk": "low",
            "recommendations": []
        }

        # Évaluer chaque modalité
        for modality in ["face", "fingerprint", "voice"]:
            if attack_type == AttackType.TEMPLATE_ATTACK:
                vuln = base_vulnerabilities[attack_type]["all"]
            else:
                vuln = base_vulnerabilities[attack_type].get(modality, {"base_risk": "medium", "current_mitigations": []})

            # Ajuster le risque basé sur la configuration
            risk_level = self._calculate_risk_level(vuln["base_risk"],
                                                   vuln["current_mitigations"],
                                                   system_configuration)

            assessment["modalities"][modality] = {
                "base_risk": vuln["base_risk"],
                "current_risk": risk_level,
                "mitigations": vuln["current_mitigations"]
            }

            if risk_level in ["high", "critical"]:
                assessment["overall_risk"] = "high"
                assessment["recommendations"].append(
                    f"Améliorer la protection contre {attack_type.value} pour {modality}"
                )

        return assessment

    def _calculate_risk_level(self, base_risk: str, mitigations: List[str],
                            configuration: Dict) -> str:
        """
        Calcule le niveau de risque ajusté

        Args:
            base_risk: Risque de base
            mitigations: Mesures de mitigation
            configuration: Configuration système

        Returns:
            str: Niveau de risque ajusté
        """
        risk_scores = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        score = risk_scores.get(base_risk, 2)

        # Réduire le score basé sur les mitigations
        mitigation_effectiveness = {
            "encryption": 1,
            "multi_capture": 0.5,
            "quality_check": 0.3,
            "liveness_check": 0.7,
            "access_control": 0.8,
            "motion_detection": 0.6
        }

        for mitigation in mitigations:
            if mitigation in configuration.get("active_mitigations", []):
                score -= mitigation_effectiveness.get(mitigation, 0.2)

        score = max(1, min(4, score))

        # Convertir en niveau
        if score <= 1.5:
            return "low"
        elif score <= 2.5:
            return "medium"
        elif score <= 3.5:
            return "high"
        else:
            return "critical"

    def analyze_bias_risks(self, test_results: Dict) -> Dict:
        """
        Analyse les risques de biais dans les résultats de test

        Args:
            test_results: Résultats des tests biométriques

        Returns:
            Dict: Analyse des biais
        """
        analysis = {
            "bias_analysis_date": datetime.now().isoformat(),
            "demographic_biases": {},
            "performance_biases": [],
            "recommendations": []
        }

        # Analyser les biais démographiques
        if "demographic_data" in test_results:
            demo_data = test_results["demographic_data"]

            # Biais de genre
            if "gender" in demo_data:
                male_acc = demo_data["gender"].get("male_accuracy", 0)
                female_acc = demo_data["gender"].get("female_accuracy", 0)
                gender_bias = abs(male_acc - female_acc)

                analysis["demographic_biases"]["gender"] = {
                    "male_accuracy": male_acc,
                    "female_accuracy": female_acc,
                    "bias_magnitude": gender_bias,
                    "significant_bias": gender_bias > 5
                }

                if gender_bias > 5:
                    analysis["performance_biases"].append({
                        "type": "gender_bias",
                        "magnitude": gender_bias,
                        "impact": "medium",
                        "recommendation": "Balanced gender representation in training data"
                    })

            # Biais d'âge
            if "age" in demo_data:
                young_acc = demo_data["age"].get("young_accuracy", 0)
                elderly_acc = demo_data["age"].get("elderly_accuracy", 0)
                age_bias = abs(young_acc - elderly_acc)

                analysis["demographic_biases"]["age"] = {
                    "young_accuracy": young_acc,
                    "elderly_accuracy": elderly_acc,
                    "bias_magnitude": age_bias,
                    "significant_bias": age_bias > 5
                }

                if age_bias > 5:
                    analysis["performance_biases"].append({
                        "type": "age_bias",
                        "magnitude": age_bias,
                        "impact": "high",
                        "recommendation": "Age-diverse training dataset required"
                    })

        # Biais de qualité d'acquisition
        if "quality_bias" in test_results:
            quality_data = test_results["quality_bias"]
            low_quality_acc = quality_data.get("low_quality_accuracy", 0)
            high_quality_acc = quality_data.get("high_quality_accuracy", 0)
            quality_bias = abs(low_quality_acc - high_quality_acc)

            if quality_bias > 10:
                analysis["performance_biases"].append({
                    "type": "quality_bias",
                    "magnitude": quality_bias,
                    "impact": "high",
                    "recommendation": "Implement quality-based decision thresholds"
                })

        # Générer recommandations générales
        if analysis["performance_biases"]:
            analysis["recommendations"].extend([
                "Conduct regular bias audits",
                "Implement fairness-aware algorithms",
                "Diversify training data",
                "Monitor performance across demographic groups"
            ])

        return analysis

    def generate_security_audit_report(self, system_config: Dict,
                                     test_results: Dict) -> Dict:
        """
        Génère un rapport d'audit de sécurité complet

        Args:
            system_config: Configuration du système
            test_results: Résultats des tests

        Returns:
            Dict: Rapport d'audit de sécurité
        """
        report = {
            "audit_date": datetime.now().isoformat(),
            "system_overview": {
                "modalities": ["face", "fingerprint", "voice"],
                "encryption": "AES-256",
                "authentication": "JWT + RBAC",
                "database": "PostgreSQL"
            },
            "attack_assessments": {},
            "bias_analysis": self.analyze_bias_risks(test_results),
            "overall_security_score": 0,
            "critical_findings": [],
            "recommendations": []
        }

        # Évaluer les vulnérabilités aux attaques
        for attack_type in AttackType:
            assessment = self.assess_attack_vulnerability(attack_type, system_config)
            report["attack_assessments"][attack_type.value] = assessment

            if assessment["overall_risk"] in ["high", "critical"]:
                report["critical_findings"].append({
                    "type": "attack_vulnerability",
                    "attack_type": attack_type.value,
                    "risk_level": assessment["overall_risk"],
                    "description": f"High vulnerability to {attack_type.value} attacks"
                })

        # Calculer le score de sécurité global
        security_scores = []
        for assessment in report["attack_assessments"].values():
            risk_scores = {"low": 4, "medium": 3, "high": 2, "critical": 1}
            security_scores.append(risk_scores.get(assessment["overall_risk"], 3))

        report["overall_security_score"] = int(np.mean(security_scores) * 25)  # 0-100 scale

        # Générer recommandations
        if report["overall_security_score"] < 70:
            report["recommendations"].extend([
                "Implement multi-factor authentication",
                "Add liveness detection for all modalities",
                "Regular security penetration testing",
                "Implement rate limiting on API endpoints"
            ])

        if report["bias_analysis"]["performance_biases"]:
            report["recommendations"].extend([
                "Conduct demographic bias analysis",
                "Implement fairness constraints",
                "Regular model retraining with diverse data"
            ])

        return report

    def simulate_attack_scenario(self, attack_type: AttackType,
                               modality: str, difficulty: str = "medium") -> Dict:
        """
        Simule un scénario d'attaque pour évaluation

        Args:
            attack_type: Type d'attaque
            modality: Modalité ciblée
            difficulty: Difficulté de l'attaque (easy, medium, hard)

        Returns:
            Dict: Résultats de la simulation
        """
        # Simulation simplifiée (en production, utiliser des datasets d'attaque réels)
        base_success_rates = {
            "easy": {"face": 0.8, "fingerprint": 0.6, "voice": 0.7},
            "medium": {"face": 0.4, "fingerprint": 0.2, "voice": 0.3},
            "hard": {"face": 0.1, "fingerprint": 0.05, "voice": 0.1}
        }

        success_rate = base_success_rates.get(difficulty, {}).get(modality, 0.3)

        # Ajuster basé sur le type d'attaque
        attack_multipliers = {
            AttackType.SPOOFING: 1.0,
            AttackType.REPLAY_ATTACK: 0.8,
            AttackType.TEMPLATE_ATTACK: 0.2,
            AttackType.PRESENTATION_ATTACK: 0.9
        }

        adjusted_success = success_rate * attack_multipliers.get(attack_type, 1.0)

        return {
            "attack_type": attack_type.value,
            "target_modality": modality,
            "difficulty": difficulty,
            "simulated_success_rate": adjusted_success,
            "detection_rate": 1 - adjusted_success,
            "recommendations": [
                "Implement anti-spoofing measures" if adjusted_success > 0.5 else "Current protections adequate",
                "Regular security testing required",
                "Monitor attack patterns"
            ]
        }
