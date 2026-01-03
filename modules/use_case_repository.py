"""
Module de documentation des cas d'usage
Définition formelle des acteurs, scénarios et exigences
"""
from enum import Enum
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from datetime import datetime


class ActorRole(Enum):
    """Rôles des acteurs du système"""
    ADMINISTRATOR = "administrator"
    AGENT = "agent"
    BENEFICIARY = "beneficiary"
    AUDITOR = "auditor"


class ScenarioType(Enum):
    """Types de scénarios d'utilisation"""
    NORMAL = "normal"
    ALTERNATIVE = "alternative"
    EXCEPTIONAL = "exceptional"


class RiskCategory(Enum):
    """Catégories de risques"""
    SECURITY = "security"
    PRIVACY = "privacy"
    BIOMETRIC = "biometric"
    OPERATIONAL = "operational"
    ETHICAL = "ethical"


@dataclass
class Actor:
    """Définition d'un acteur du système"""
    role: ActorRole
    name: str
    description: str
    permissions: Set[str]
    responsibilities: List[str]
    access_level: str

    def has_permission(self, permission: str) -> bool:
        """Vérifie si l'acteur a une permission spécifique"""
        return permission in self.permissions


@dataclass
class UseCase:
    """Définition d'un cas d'usage"""
    id: str
    name: str
    description: str
    primary_actor: ActorRole
    secondary_actors: List[ActorRole]
    preconditions: List[str]
    postconditions: List[str]
    main_flow: List[str]
    alternative_flows: Dict[str, List[str]]
    exceptions: Dict[str, str]


@dataclass
class Risk:
    """Définition d'un risque"""
    id: str
    category: RiskCategory
    name: str
    description: str
    likelihood: str  # low, medium, high, critical
    impact: str      # low, medium, high, critical
    affected_assets: List[str]
    mitigation_measures: List[str]
    responsible_party: ActorRole


class UseCaseRepository:
    """Repository des cas d'usage et acteurs"""

    def __init__(self):
        self.actors = self._define_actors()
        self.use_cases = self._define_use_cases()
        self.risks = self._define_risks()
        self.business_requirements = self._define_business_requirements()

    def _define_actors(self) -> Dict[ActorRole, Actor]:
        """Définit tous les acteurs du système"""
        return {
            ActorRole.ADMINISTRATOR: Actor(
                role=ActorRole.ADMINISTRATOR,
                name="Administrateur Système",
                description="Gestionnaire global du système biométrique",
                permissions={
                    "user:create", "user:read", "user:update", "user:delete",
                    "system:configure", "audit:read", "audit:export",
                    "metrics:view", "metrics:export", "security:manage"
                },
                responsibilities=[
                    "Configuration du système",
                    "Gestion des utilisateurs",
                    "Supervision des opérations",
                    "Maintenance et mises à jour",
                    "Gestion des incidents de sécurité"
                ],
                access_level="full"
            ),

            ActorRole.AGENT: Actor(
                role=ActorRole.AGENT,
                name="Agent d'Enrôlement",
                description="Opérateur chargé de l'enrôlement et vérification des bénéficiaires",
                permissions={
                    "beneficiary:create", "beneficiary:read", "beneficiary:update",
                    "biometric:enroll", "biometric:verify", "biometric:identify",
                    "consent:record", "audit:read"
                },
                responsibilities=[
                    "Enrôlement des bénéficiaires",
                    "Vérification d'identité",
                    "Collecte du consentement",
                    "Gestion des données biométriques",
                    "Signalement des anomalies"
                ],
                access_level="operational"
            ),

            ActorRole.BENEFICIARY: Actor(
                role=ActorRole.BENEFICIARY,
                name="Bénéficiaire",
                description="Personne bénéficiant de l'aide sociale utilisant le système biométrique",
                permissions={
                    "self:consent", "self:data_access", "self:data_rectification",
                    "self:data_deletion", "self:complaint"
                },
                responsibilities=[
                    "Fournir des données biométriques valides",
                    "Donner un consentement éclairé",
                    "Signaler les erreurs de reconnaissance",
                    "Exercer ses droits RGPD"
                ],
                access_level="limited"
            ),

            ActorRole.AUDITOR: Actor(
                role=ActorRole.AUDITOR,
                name="Auditeur",
                description="Contrôleur chargé de la vérification de la conformité et des performances",
                permissions={
                    "audit:read", "audit:export", "metrics:view", "metrics:export",
                    "compliance:check", "logs:access"
                },
                responsibilities=[
                    "Audit des opérations",
                    "Vérification de la conformité",
                    "Analyse des performances",
                    "Détection des anomalies",
                    "Rapport sur les risques"
                ],
                access_level="read-only"
            )
        }

    def _define_use_cases(self) -> Dict[str, UseCase]:
        """Définit tous les cas d'usage du système"""
        return {
            "UC001": UseCase(
                id="UC001",
                name="Enrôlement Biométrique",
                description="Enregistrement initial d'un bénéficiaire avec collecte de données biométriques",
                primary_actor=ActorRole.AGENT,
                secondary_actors=[ActorRole.BENEFICIARY],
                preconditions=[
                    "Le bénéficiaire est éligible à l'aide sociale",
                    "Le consentement peut être recueilli",
                    "Les équipements biométriques sont opérationnels"
                ],
                postconditions=[
                    "Les descripteurs biométriques sont stockés de manière sécurisée",
                    "Un identifiant unique est généré",
                    "Le consentement est enregistré"
                ],
                main_flow=[
                    "1. L'agent vérifie l'identité civile du bénéficiaire",
                    "2. L'agent explique le processus biométrique et recueille le consentement",
                    "3. Capture des données faciales (10 images)",
                    "4. Capture de l'empreinte digitale",
                    "5. Enregistrement vocal optionnel",
                    "6. Extraction et chiffrement des descripteurs",
                    "7. Génération de l'identifiant unique (BioID)",
                    "8. Stockage sécurisé des données",
                    "9. Remise de la carte d'identification au bénéficiaire"
                ],
                alternative_flows={
                    "A1 - Échec capture faciale": [
                        "3a. Si la capture faciale échoue après 3 tentatives",
                        "3b. Utiliser uniquement les autres modalités disponibles",
                        "3c. Noter la limitation dans le dossier"
                    ],
                    "A2 - Refus consentement": [
                        "2a. Si le bénéficiaire refuse le consentement",
                        "2b. Expliquer les conséquences (aide non distribuée)",
                        "2c. Terminer le processus sans enrôlement"
                    ]
                },
                exceptions={
                    "E1 - Équipement défaillant": "Reporter l'enrôlement et utiliser procédure manuelle",
                    "E2 - Données biométriques invalides": "Refuser l'enrôlement et proposer alternatives"
                }
            ),

            "UC002": UseCase(
                id="UC002",
                name="Vérification d'Identité",
                description="Vérification de l'identité lors de la distribution d'aide",
                primary_actor=ActorRole.AGENT,
                secondary_actors=[ActorRole.BENEFICIARY],
                preconditions=[
                    "Le bénéficiaire présente sa carte d'identification",
                    "Le BioID est valide",
                    "Les équipements sont opérationnels"
                ],
                postconditions=[
                    "L'identité est confirmée ou rejetée",
                    "L'opération est tracée en audit",
                    "Le résultat est enregistré"
                ],
                main_flow=[
                    "1. L'agent scanne ou saisit le BioID",
                    "2. Capture des données biométriques en temps réel",
                    "3. Comparaison avec les descripteurs stockés",
                    "4. Calcul du score de similarité",
                    "5. Application du seuil de décision",
                    "6. Affichage du résultat (accepté/rejeté)",
                    "7. Enregistrement de l'opération en audit"
                ],
                alternative_flows={
                    "A1 - Score borderline": [
                        "5a. Si le score est proche du seuil",
                        "5b. Demander une vérification supplémentaire",
                        "5c. Ou permettre une décision manuelle"
                    ],
                    "A2 - Échec technique": [
                        "2a. Si la capture échoue",
                        "2b. Proposer une vérification alternative",
                        "2c. Ou rejeter la demande"
                    ]
                },
                exceptions={
                    "E1 - BioID inconnu": "Alerter et vérifier l'authenticité de la carte",
                    "E2 - Tentative de fraude détectée": "Refuser et signaler pour investigation"
                }
            ),

            "UC003": UseCase(
                id="UC003",
                name="Administration Système",
                description="Gestion et configuration du système biométrique",
                primary_actor=ActorRole.ADMINISTRATOR,
                secondary_actors=[],
                preconditions=[
                    "Authentification administrateur réussie",
                    "Accès au panneau d'administration"
                ],
                postconditions=[
                    "Les modifications sont appliquées",
                    "Les changements sont tracés en audit"
                ],
                main_flow=[
                    "1. Accès au panneau d'administration",
                    "2. Consultation des métriques système",
                    "3. Gestion des utilisateurs et rôles",
                    "4. Configuration des seuils biométriques",
                    "5. Revue des logs d'audit",
                    "6. Export des rapports de conformité"
                ],
                alternative_flows={},
                exceptions={
                    "E1 - Droits insuffisants": "Refuser l'accès et logger l'incident"
                }
            )
        }

    def _define_risks(self) -> Dict[str, Risk]:
        """Définit tous les risques identifiés"""
        return {
            "R001": Risk(
                id="R001",
                category=RiskCategory.SECURITY,
                name="Attaque par Présentation",
                description="Tentative de tromper le système avec des faux biométriques (photos, empreintes artificielles)",
                likelihood="high",
                impact="high",
                affected_assets=["Authentification", "Intégrité des données"],
                mitigation_measures=[
                    "Détection de vivacité (liveness detection)",
                    "Contrôle qualité des captures",
                    "Seuils de décision adaptés",
                    "Multi-modalité obligatoire"
                ],
                responsible_party=ActorRole.ADMINISTRATOR
            ),

            "R002": Risk(
                id="R002",
                category=RiskCategory.PRIVACY,
                name="Fuite de Données Biométriques",
                description="Divulgation accidentelle ou malveillante des descripteurs biométriques",
                likelihood="medium",
                impact="critical",
                affected_assets=["Vie privée des bénéficiaires", "Confiance système"],
                mitigation_measures=[
                    "Chiffrement AES-256 des descripteurs",
                    "Contrôle d'accès strict (RBAC)",
                    "Audit complet des accès",
                    "Minimisation des données stockées"
                ],
                responsible_party=ActorRole.ADMINISTRATOR
            ),

            "R003": Risk(
                id="R003",
                category=RiskCategory.BIOMETRIC,
                name="Biais Démographiques",
                description="Performance variable selon les caractéristiques démographiques (âge, genre, ethnie)",
                likelihood="medium",
                impact="medium",
                affected_assets=["Équité du système", "Accessibilité"],
                mitigation_measures=[
                    "Diversification des données d'entraînement",
                    "Tests d'équité réguliers",
                    "Seuils adaptatifs",
                    "Alternatives non-biométriques"
                ],
                responsible_party=ActorRole.AUDITOR
            ),

            "R004": Risk(
                id="R004",
                category=RiskCategory.ETHICAL,
                name="Exclusion des Vulnérables",
                description="Groupes défavorisés (handicapés, personnes âgées) exclus du système",
                likelihood="low",
                impact="high",
                affected_assets=["Droits humains", "Accès aux services sociaux"],
                mitigation_measures=[
                    "Évaluation d'impact sur les droits",
                    "Procédures alternatives",
                    "Formation des agents",
                    "Mécanismes de plainte"
                ],
                responsible_party=ActorRole.ADMINISTRATOR
            )
        }

    def _define_business_requirements(self) -> Dict[str, Dict]:
        """Définit les exigences métier"""
        return {
            "BR001": {
                "id": "BR001",
                "category": "functional",
                "description": "Le système doit supporter l'enrôlement multimodal (visage, empreinte, voix)",
                "priority": "high",
                "verification_method": "test_integration"
            },

            "BR002": {
                "id": "BR002",
                "category": "security",
                "description": "Toutes les données biométriques doivent être chiffrées au repos",
                "priority": "critical",
                "verification_method": "security_audit"
            },

            "BR003": {
                "id": "BR003",
                "category": "compliance",
                "description": "Le système doit être conforme RGPD et Loi 09-08",
                "priority": "high",
                "verification_method": "compliance_audit"
            },

            "BR004": {
                "id": "BR004",
                "category": "performance",
                "description": "Taux d'erreur global (EER) < 5% pour toutes les modalités",
                "priority": "high",
                "verification_method": "performance_testing"
            },

            "BR005": {
                "id": "BR005",
                "category": "usability",
                "description": "Temps d'enrôlement < 5 minutes, vérification < 30 secondes",
                "priority": "medium",
                "verification_method": "usability_testing"
            }
        }

    def get_actor(self, role: ActorRole) -> Optional[Actor]:
        """Récupère la définition d'un acteur"""
        return self.actors.get(role)

    def get_use_case(self, use_case_id: str) -> Optional[UseCase]:
        """Récupère la définition d'un cas d'usage"""
        return self.use_cases.get(use_case_id)

    def get_risk(self, risk_id: str) -> Optional[Risk]:
        """Récupère la définition d'un risque"""
        return self.risks.get(risk_id)

    def get_all_actors(self) -> Dict[ActorRole, Actor]:
        """Récupère tous les acteurs"""
        return self.actors.copy()

    def get_all_use_cases(self) -> Dict[str, UseCase]:
        """Récupère tous les cas d'usage"""
        return self.use_cases.copy()

    def get_risks_by_category(self, category: RiskCategory) -> List[Risk]:
        """Récupère les risques par catégorie"""
        return [risk for risk in self.risks.values() if risk.category == category]

    def validate_permission(self, actor_role: ActorRole, permission: str) -> bool:
        """Valide si un acteur a une permission spécifique"""
        actor = self.get_actor(actor_role)
        return actor.has_permission(permission) if actor else False

    def generate_requirements_traceability_matrix(self) -> Dict:
        """
        Génère une matrice de traçabilité des exigences

        Returns:
            Dict: Matrice de traçabilité
        """
        return {
            "generated_at": datetime.now().isoformat(),
            "business_requirements": self.business_requirements,
            "traceability": {
                "BR001": ["UC001", "R001"],  # Enrôlement multimodal
                "BR002": ["R002", "R001"],   # Sécurité des données
                "BR003": ["R002", "R004"],   # Conformité légale
                "BR004": ["R003", "UC002"],  # Performance
                "BR005": ["UC001", "UC002"]  # Utilisabilité
            },
            "coverage_analysis": self._analyze_requirements_coverage()
        }

    def _analyze_requirements_coverage(self) -> Dict:
        """Analyse la couverture des exigences"""
        total_requirements = len(self.business_requirements)
        covered_requirements = len([r for r in self.business_requirements.values()
                                   if r.get("implementation_status") == "implemented"])

        return {
            "total_requirements": total_requirements,
            "implemented_requirements": covered_requirements,
            "coverage_percentage": (covered_requirements / total_requirements * 100) if total_requirements > 0 else 0,
            "gap_analysis": [
                req_id for req_id, req in self.business_requirements.items()
                if req.get("implementation_status") != "implemented"
            ]
        }

    def export_use_case_documentation(self) -> Dict:
        """
        Exporte la documentation complète des cas d'usage

        Returns:
            Dict: Documentation complète
        """
        return {
            "export_date": datetime.now().isoformat(),
            "system_name": "BioID - Système d'Identification Biométrique",
            "version": "2.0",
            "actors": {role.value: {
                "name": actor.name,
                "description": actor.description,
                "permissions": list(actor.permissions),
                "responsibilities": actor.responsibilities,
                "access_level": actor.access_level
            } for role, actor in self.actors.items()},
            "use_cases": {uc_id: {
                "name": uc.name,
                "description": uc.description,
                "primary_actor": uc.primary_actor.value,
                "secondary_actors": [actor.value for actor in uc.secondary_actors],
                "preconditions": uc.preconditions,
                "postconditions": uc.postconditions,
                "main_flow": uc.main_flow,
                "alternative_flows": uc.alternative_flows,
                "exceptions": uc.exceptions
            } for uc_id, uc in self.use_cases.items()},
            "risks": {risk_id: {
                "category": risk.category.value,
                "name": risk.name,
                "description": risk.description,
                "likelihood": risk.likelihood,
                "impact": risk.impact,
                "affected_assets": risk.affected_assets,
                "mitigation_measures": risk.mitigation_measures,
                "responsible_party": risk.responsible_party.value
            } for risk_id, risk in self.risks.items()},
            "business_requirements": self.business_requirements,
            "traceability_matrix": self.generate_requirements_traceability_matrix()
        }
