#!/usr/bin/env python3
"""
Script d'audit automatisé du système BIOID-MULTIMODAL
Analyse la conformité légale, sécurité et éthique

Usage:
    python audit_system.py
    python audit_system.py --full  # Audit complet avec tests
"""

import os
import json
import sys
from datetime import datetime
from typing import Dict, List, Tuple
import argparse


class SystemAuditor:
    """Auditeur automatisé du système biométrique"""

    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.results = {
            "audit_date": datetime.now().isoformat(),
            "compliance": {},
            "security": {},
            "privacy": {},
            "overall_score": 0,
            "critical_issues": [],
            "warnings": [],
            "recommendations": []
        }

    def run_full_audit(self) -> Dict:
        """Exécute l'audit complet"""
        print("=" * 70)
        print("  AUDIT SYSTÈME BIOMÉTRIQUE BIOID-MULTIMODAL")
        print("=" * 70)
        print(f"Date : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        # 1. Audit de conformité légale
        print("[1/6] Audit de conformité légale...")
        self.audit_legal_compliance()

        # 2. Audit de sécurité
        print("[2/6] Audit de sécurité technique...")
        self.audit_security()

        # 3. Audit de protection des données
        print("[3/6] Audit de protection des données...")
        self.audit_privacy()

        # 4. Audit de la structure des fichiers
        print("[4/6] Audit de la structure du système...")
        self.audit_file_structure()

        # 5. Vérification des modules de conformité
        print("[5/6] Vérification des modules de conformité...")
        self.audit_compliance_modules()

        # 6. Calcul du score global
        print("[6/6] Calcul du score global...\n")
        self.calculate_overall_score()

        # Génération du rapport
        self.generate_report()

        return self.results

    def audit_legal_compliance(self):
        """Audit de conformité légale (Loi 09-08, RGPD)"""
        compliance = {
            "score": 0,
            "max_score": 10,
            "checks": []
        }

        # 1. Vérifier consentement
        consent_file = os.path.join(self.base_dir, "data/compliance/consents.json")
        if os.path.exists(consent_file):
            compliance["checks"].append({
                "name": "Module de consentement présent",
                "status": "[OK] PASS",
                "points": 1
            })
            compliance["score"] += 1
        else:
            compliance["checks"].append({
                "name": "Module de consentement absent",
                "status": "[X] FAIL",
                "points": 0
            })
            self.results["critical_issues"].append(
                "Module de gestion du consentement manquant"
            )

        # 2. Vérifier politique de rétention
        retention_file = os.path.join(self.base_dir, "data/compliance/retention_policies.json")
        if os.path.exists(retention_file):
            compliance["checks"].append({
                "name": "Politique de rétention définie",
                "status": "[OK] PASS",
                "points": 1
            })
            compliance["score"] += 1

            # Vérifier contenu
            with open(retention_file, 'r') as f:
                policies = json.load(f)
                if "beneficiaries" in policies:
                    days = policies["beneficiaries"].get("retention_days", 0)
                    if days > 0 and days <= 1825:  # 5 ans max
                        compliance["checks"].append({
                            "name": f"Rétention limitée à {days} jours",
                            "status": "[OK] PASS",
                            "points": 1
                        })
                        compliance["score"] += 1
                    else:
                        self.results["warnings"].append(
                            f"Durée de rétention excessive : {days} jours"
                        )
        else:
            self.results["critical_issues"].append(
                "Politique de rétention des données manquante"
            )

        # 3. Vérifier module d'audit
        audit_module = os.path.join(self.base_dir, "modules/audit.py")
        if os.path.exists(audit_module):
            compliance["checks"].append({
                "name": "Module d'audit présent",
                "status": "[OK] PASS",
                "points": 1
            })
            compliance["score"] += 1
        else:
            self.results["critical_issues"].append("Module d'audit manquant")

        # 4. Vérifier logs d'audit
        audit_dir = os.path.join(self.base_dir, "data/audit")
        if os.path.exists(audit_dir) and os.listdir(audit_dir):
            compliance["checks"].append({
                "name": "Journalisation active",
                "status": "[OK] PASS",
                "points": 1
            })
            compliance["score"] += 1
        else:
            self.results["warnings"].append("Aucun log d'audit trouvé")

        # 5. Vérifier notice d'information
        # À implémenter : vérifier présence de templates d'information

        # 6. Vérifier déclaration CNDP (manuel)
        compliance["checks"].append({
            "name": "Déclaration CNDP (vérification manuelle requise)",
            "status": "[!] MANUAL",
            "points": 0
        })
        self.results["critical_issues"].append(
            "Vérifier que la déclaration CNDP a été effectuée"
        )

        compliance["percentage"] = (compliance["score"] / compliance["max_score"]) * 100
        self.results["compliance"] = compliance

    def audit_security(self):
        """Audit de sécurité technique"""
        security = {
            "score": 0,
            "max_score": 15,
            "checks": []
        }

        # 1. Vérifier module de sécurité
        security_module = os.path.join(self.base_dir, "modules/security.py")
        if os.path.exists(security_module):
            security["checks"].append({
                "name": "Module de sécurité présent",
                "status": "[OK] PASS",
                "points": 1
            })
            security["score"] += 1

            # Vérifier chiffrement dans le code
            with open(security_module, 'r', encoding='utf-8') as f:
                content = f.read()
                if "AES" in content or "Fernet" in content:
                    security["checks"].append({
                        "name": "Chiffrement AES implémenté",
                        "status": "[OK] PASS",
                        "points": 2
                    })
                    security["score"] += 2

                if "PBKDF2" in content:
                    security["checks"].append({
                        "name": "Dérivation de clé sécurisée (PBKDF2)",
                        "status": "[OK] PASS",
                        "points": 1
                    })
                    security["score"] += 1

        # 2. Vérifier RBAC
        rbac_module = os.path.join(self.base_dir, "modules/rbac.py")
        if os.path.exists(rbac_module):
            security["checks"].append({
                "name": "Contrôle d'accès RBAC présent",
                "status": "[OK] PASS",
                "points": 2
            })
            security["score"] += 2
        else:
            self.results["critical_issues"].append("RBAC non implémenté")

        # 3. Vérifier stockage des clés
        keys_dir = os.path.join(self.base_dir, "data/keys")
        if os.path.exists(keys_dir):
            security["checks"].append({
                "name": "Répertoire de clés sécurisé présent",
                "status": "[OK] PASS",
                "points": 1
            })
            security["score"] += 1

            # Vérifier permissions (sous Linux/Unix uniquement)
            if sys.platform != "win32":
                stat_info = os.stat(keys_dir)
                if oct(stat_info.st_mode)[-3:] == "700":
                    security["checks"].append({
                        "name": "Permissions clés restrictives (700)",
                        "status": "[OK] PASS",
                        "points": 1
                    })
                    security["score"] += 1
                else:
                    self.results["warnings"].append(
                        "Permissions du répertoire de clés trop permissives"
                    )

        # 4. Vérifier HTTPS dans config
        config_file = os.path.join(self.base_dir, "config.py")
        if os.path.exists(config_file):
            with open(config_file, 'r', encoding='utf-8') as f:
                content = f.read()
                if "HTTPS" in content or "SSL" in content or "TLS" in content:
                    security["checks"].append({
                        "name": "Configuration HTTPS/TLS",
                        "status": "[OK] PASS",
                        "points": 2
                    })
                    security["score"] += 2
                else:
                    security["checks"].append({
                        "name": "HTTPS/TLS non configuré",
                        "status": "[X] FAIL",
                        "points": 0
                    })
                    self.results["critical_issues"].append(
                        "HTTPS/TLS doit être implémenté pour la production"
                    )

        # 5. Vérifier pas de secrets hardcodés
        app_file = os.path.join(self.base_dir, "app.py")
        if os.path.exists(app_file):
            with open(app_file, 'r', encoding='utf-8') as f:
                content = f.read()
                # Chercher patterns de secrets
                if 'SECRET_KEY = "' in content or "password = '" in content:
                    self.results["warnings"].append(
                        "Secrets potentiellement hardcodés dans app.py"
                    )

        # 6. Vérifier module d'évaluation des risques
        risk_module = os.path.join(self.base_dir, "modules/risk_assessment.py")
        if os.path.exists(risk_module):
            security["checks"].append({
                "name": "Module d'évaluation des risques",
                "status": "[OK] PASS",
                "points": 2
            })
            security["score"] += 2

        security["percentage"] = (security["score"] / security["max_score"]) * 100
        self.results["security"] = security

    def audit_privacy(self):
        """Audit de protection de la vie privée"""
        privacy = {
            "score": 0,
            "max_score": 10,
            "checks": []
        }

        # 1. Vérifier module de compliance
        compliance_module = os.path.join(self.base_dir, "modules/compliance.py")
        if os.path.exists(compliance_module):
            privacy["checks"].append({
                "name": "Module de conformité présent",
                "status": "[OK] PASS",
                "points": 2
            })
            privacy["score"] += 2

            # Vérifier fonctions de vie privée
            with open(compliance_module, 'r', encoding='utf-8') as f:
                content = f.read()

                if "withdraw_consent" in content:
                    privacy["checks"].append({
                        "name": "Retrait du consentement implémenté",
                        "status": "[OK] PASS",
                        "points": 1
                    })
                    privacy["score"] += 1

                if "privacy_impact" in content or "PIA" in content:
                    privacy["checks"].append({
                        "name": "Évaluation d'impact vie privée (PIA)",
                        "status": "[OK] PASS",
                        "points": 2
                    })
                    privacy["score"] += 2

        # 2. Vérifier anonymisation
        if os.path.exists(os.path.join(self.base_dir, "modules/security.py")):
            with open(os.path.join(self.base_dir, "modules/security.py"), 'r', encoding='utf-8') as f:
                content = f.read()
                if "anonymize" in content or "pseudonymize" in content:
                    privacy["checks"].append({
                        "name": "Fonctions d'anonymisation présentes",
                        "status": "[OK] PASS",
                        "points": 1
                    })
                    privacy["score"] += 1

        # 3. Vérifier pas de stockage d'images brutes
        faces_dir = os.path.join(self.base_dir, "data/faces")
        fingerprints_dir = os.path.join(self.base_dir, "data/fingerprints")

        raw_images_found = False
        if os.path.exists(faces_dir) and os.listdir(faces_dir):
            raw_images_found = True
        if os.path.exists(fingerprints_dir) and os.listdir(fingerprints_dir):
            raw_images_found = True

        if raw_images_found:
            privacy["checks"].append({
                "name": "Images brutes détectées",
                "status": "[!] WARNING",
                "points": 0
            })
            self.results["warnings"].append(
                "Images biométriques brutes stockées - violation de minimisation des données"
            )
        else:
            privacy["checks"].append({
                "name": "Pas d'images brutes stockées",
                "status": "[OK] PASS",
                "points": 2
            })
            privacy["score"] += 2

        # 4. Vérifier base de données chiffrée
        db_file = os.path.join(self.base_dir, "data/database/beneficiaries.json")
        if os.path.exists(db_file):
            with open(db_file, 'r') as f:
                try:
                    data = json.load(f)
                    # Vérifier si les données sont chiffrées (base64 long)
                    if "beneficiaries" in data and len(data["beneficiaries"]) > 0:
                        first = data["beneficiaries"][0]
                        if "face_encoding" in first and isinstance(first["face_encoding"], str):
                            if len(first["face_encoding"]) > 100:  # Probablement chiffré
                                privacy["checks"].append({
                                    "name": "Descripteurs biométriques chiffrés",
                                    "status": "[OK] PASS",
                                    "points": 2
                                })
                                privacy["score"] += 2
                except:
                    pass

        privacy["percentage"] = (privacy["score"] / privacy["max_score"]) * 100
        self.results["privacy"] = privacy

    def audit_file_structure(self):
        """Vérifie la structure des fichiers et répertoires"""
        required_structure = {
            "modules": ["audit.py", "compliance.py", "security.py", "rbac.py"],
            "data/compliance": ["consents.json", "retention_policies.json"],
            "data/audit": [],
            "data/keys": []
        }

        missing = []
        for directory, files in required_structure.items():
            dir_path = os.path.join(self.base_dir, directory)
            if not os.path.exists(dir_path):
                missing.append(directory)
            else:
                for file in files:
                    file_path = os.path.join(dir_path, file)
                    if not os.path.exists(file_path):
                        missing.append(f"{directory}/{file}")

        if missing:
            self.results["warnings"].append(
                f"Fichiers/répertoires manquants : {', '.join(missing)}"
            )

    def audit_compliance_modules(self):
        """Teste les modules de conformité"""
        try:
            # Importer les modules
            sys.path.insert(0, os.path.join(self.base_dir, "modules"))

            # Test module compliance
            try:
                from compliance import ComplianceManager, EthicalAssessment
                cm = ComplianceManager()
                self.results["compliance"]["modules_ok"] = True
            except Exception as e:
                self.results["warnings"].append(f"Module compliance error: {str(e)}")

            # Test module audit
            try:
                from audit import AuditLogger
                al = AuditLogger()
                self.results["compliance"]["audit_module_ok"] = True
            except Exception as e:
                self.results["warnings"].append(f"Module audit error: {str(e)}")

        except Exception as e:
            self.results["warnings"].append(f"Error importing modules: {str(e)}")

    def calculate_overall_score(self):
        """Calcule le score global de conformité"""
        scores = []

        if "compliance" in self.results:
            scores.append(self.results["compliance"].get("percentage", 0))

        if "security" in self.results:
            scores.append(self.results["security"].get("percentage", 0))

        if "privacy" in self.results:
            scores.append(self.results["privacy"].get("percentage", 0))

        if scores:
            self.results["overall_score"] = sum(scores) / len(scores)
        else:
            self.results["overall_score"] = 0

    def generate_report(self):
        """Génère le rapport d'audit"""
        print("\n" + "=" * 70)
        print("  RAPPORT D'AUDIT")
        print("=" * 70)

        # Score global
        score = self.results["overall_score"]
        if score >= 80:
            status = "[OK] CONFORME"
            color = "green"
        elif score >= 60:
            status = "[!] PARTIELLEMENT CONFORME"
            color = "yellow"
        else:
            status = "[X] NON CONFORME"
            color = "red"

        print(f"\nScore global : {score:.1f}% - {status}\n")

        # Détails par catégorie
        if "compliance" in self.results:
            comp = self.results["compliance"]
            print(f"[1] Conformité légale : {comp.get('percentage', 0):.1f}%")
            for check in comp.get("checks", []):
                print(f"    {check['status']} {check['name']}")
            print()

        if "security" in self.results:
            sec = self.results["security"]
            print(f"[2] Sécurité technique : {sec.get('percentage', 0):.1f}%")
            for check in sec.get("checks", []):
                print(f"    {check['status']} {check['name']}")
            print()

        if "privacy" in self.results:
            priv = self.results["privacy"]
            print(f"[3] Protection vie privée : {priv.get('percentage', 0):.1f}%")
            for check in priv.get("checks", []):
                print(f"    {check['status']} {check['name']}")
            print()

        # Problèmes critiques
        if self.results["critical_issues"]:
            print("[!] PROBLEMES CRITIQUES:")
            for issue in self.results["critical_issues"]:
                print(f"   - {issue}")
            print()

        # Avertissements
        if self.results["warnings"]:
            print("[!] AVERTISSEMENTS:")
            for warning in self.results["warnings"]:
                print(f"   - {warning}")
            print()

        # Recommandations
        self.generate_recommendations()
        if self.results["recommendations"]:
            print("[*] RECOMMANDATIONS:")
            for i, rec in enumerate(self.results["recommendations"], 1):
                print(f"   {i}. {rec}")
            print()

        # Sauvegarder le rapport
        report_file = os.path.join(self.base_dir, "data/audit",
                                   f"audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        os.makedirs(os.path.dirname(report_file), exist_ok=True)
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)

        print(f"Rapport sauvegardé : {report_file}")
        print("=" * 70)

    def generate_recommendations(self):
        """Génère des recommandations basées sur l'audit"""
        recs = []

        # Basé sur le score
        score = self.results["overall_score"]
        if score < 60:
            recs.append("Mise en conformité urgente requise avant production")

        # Basé sur les problèmes critiques
        if "HTTPS/TLS" in str(self.results["critical_issues"]):
            recs.append("Implémenter HTTPS/TLS immédiatement")

        if "CNDP" in str(self.results["critical_issues"]):
            recs.append("Effectuer la déclaration auprès de la CNDP avant mise en production")

        if "RBAC" in str(self.results["critical_issues"]):
            recs.append("Implémenter le contrôle d'accès basé sur les rôles")

        # Basé sur les scores de catégorie
        if self.results.get("security", {}).get("percentage", 0) < 60:
            recs.append("Renforcer la sécurité technique (chiffrement, authentification)")

        if self.results.get("privacy", {}).get("percentage", 0) < 60:
            recs.append("Améliorer la protection de la vie privée (minimisation, anonymisation)")

        # Recommandations générales
        if score < 80:
            recs.append("Réaliser un audit externe de sécurité")
            recs.append("Former le personnel à la protection des données")

        self.results["recommendations"] = recs


def main():
    """Point d'entrée principal"""
    parser = argparse.ArgumentParser(description="Audit du système BIOID-MULTIMODAL")
    parser.add_argument("--full", action="store_true", help="Audit complet avec tests")
    parser.add_argument("--json", action="store_true", help="Sortie en JSON")
    args = parser.parse_args()

    auditor = SystemAuditor()
    results = auditor.run_full_audit()

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))

    # Code de sortie basé sur le score
    score = results["overall_score"]
    if score >= 80:
        sys.exit(0)  # Success
    elif score >= 60:
        sys.exit(1)  # Warning
    else:
        sys.exit(2)  # Critical


if __name__ == "__main__":
    main()
