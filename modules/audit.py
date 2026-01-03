"""
Module d'audit et journalisation
Traçabilité des opérations biométriques
"""
import json
import os
from datetime import datetime
from enum import Enum
import hashlib


class AuditEventType(Enum):
    """Types d'événements d'audit"""
    ENROLLMENT = "enrollment"
    AUTHENTICATION = "authentication"
    IDENTIFICATION = "identification"
    VERIFICATION = "verification"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    DATA_DELETION = "data_deletion"
    CONSENT_GIVEN = "consent_given"
    CONSENT_WITHDRAWN = "consent_withdrawn"
    LOGIN = "login"
    LOGOUT = "logout"
    FAILED_AUTH = "failed_authentication"
    SECURITY_ALERT = "security_alert"


class AuditLogger:
    """Gère la journalisation des événements biométriques"""
    
    def __init__(self, log_dir="data/audit"):
        """
        Args:
            log_dir: Répertoire des logs d'audit
        """
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        
        # Fichier de log du jour
        self.current_log_file = self._get_log_file()
    
    def _get_log_file(self):
        """Retourne le fichier de log du jour"""
        date_str = datetime.now().strftime("%Y-%m-%d")
        return os.path.join(self.log_dir, f"audit_{date_str}.json")
    
    def _load_logs(self):
        """Charge les logs du fichier actuel"""
        if os.path.exists(self.current_log_file):
            with open(self.current_log_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {"logs": []}
    
    def _save_logs(self, logs):
        """Sauvegarde les logs"""
        with open(self.current_log_file, 'w', encoding='utf-8') as f:
            json.dump(logs, f, indent=2, ensure_ascii=False)
    
    def log_event(self, event_type, actor, bio_id=None, details=None, success=True, ip_address=None):
        """
        Enregistre un événement d'audit
        
        Args:
            event_type: Type d'événement (AuditEventType)
            actor: Identifiant de l'acteur (user_id, operator_id)
            bio_id: ID biométrique concerné (optionnel)
            details: Détails supplémentaires (dict)
            success: Succès de l'opération
            ip_address: Adresse IP source
            
        Returns:
            str: ID de l'événement
        """
        # Mettre à jour le fichier de log si changement de jour
        self.current_log_file = self._get_log_file()
        
        event_id = hashlib.sha256(
            f"{datetime.now().isoformat()}{actor}{event_type}".encode()
        ).hexdigest()[:16]
        
        event = {
            "event_id": event_id,
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type.value if isinstance(event_type, AuditEventType) else event_type,
            "actor": actor,
            "bio_id": bio_id,
            "success": success,
            "ip_address": ip_address,
            "details": details or {}
        }
        
        # Sauvegarder
        logs = self._load_logs()
        logs["logs"].append(event)
        self._save_logs(logs)
        
        # Log console
        status = "✓" if success else "✗"
        print(f"[AUDIT] {status} {event_type.value if isinstance(event_type, AuditEventType) else event_type}: {actor} -> {bio_id or 'N/A'}")
        
        return event_id
    
    def log_enrollment(self, operator_id, bio_id, modalities, ip_address=None):
        """Log un enrôlement"""
        return self.log_event(
            AuditEventType.ENROLLMENT,
            actor=operator_id,
            bio_id=bio_id,
            details={"modalities": modalities},
            ip_address=ip_address
        )
    
    def log_verification(self, bio_id, success, confidence, ip_address=None):
        """Log une vérification (1:1)"""
        return self.log_event(
            AuditEventType.VERIFICATION,
            actor="system",
            bio_id=bio_id,
            details={"confidence": confidence},
            success=success,
            ip_address=ip_address
        )
    
    def log_identification(self, query_hash, found_bio_id, confidence, ip_address=None):
        """Log une identification (1:N)"""
        return self.log_event(
            AuditEventType.IDENTIFICATION,
            actor="system",
            bio_id=found_bio_id,
            details={"query_hash": query_hash, "confidence": confidence},
            success=found_bio_id is not None,
            ip_address=ip_address
        )
    
    def log_data_access(self, actor, bio_id, access_type, ip_address=None):
        """Log un accès aux données"""
        return self.log_event(
            AuditEventType.DATA_ACCESS,
            actor=actor,
            bio_id=bio_id,
            details={"access_type": access_type},
            ip_address=ip_address
        )
    
    def log_security_alert(self, alert_type, details, ip_address=None):
        """Log une alerte de sécurité"""
        return self.log_event(
            AuditEventType.SECURITY_ALERT,
            actor="system",
            details={"alert_type": alert_type, **details},
            success=False,
            ip_address=ip_address
        )
    
    def get_logs(self, start_date=None, end_date=None, event_type=None, bio_id=None):
        """
        Récupère les logs avec filtres
        
        Args:
            start_date: Date de début (datetime)
            end_date: Date de fin (datetime)
            event_type: Filtrer par type
            bio_id: Filtrer par ID biométrique
            
        Returns:
            list: Liste des événements
        """
        all_logs = []
        
        # Parcourir les fichiers de log
        for filename in os.listdir(self.log_dir):
            if not filename.startswith("audit_") or not filename.endswith(".json"):
                continue
            
            filepath = os.path.join(self.log_dir, filename)
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
                all_logs.extend(data.get("logs", []))
        
        # Appliquer les filtres
        filtered = []
        for log in all_logs:
            # Filtre date
            log_date = datetime.fromisoformat(log["timestamp"])
            if start_date and log_date < start_date:
                continue
            if end_date and log_date > end_date:
                continue
            
            # Filtre type
            if event_type and log["event_type"] != event_type:
                continue
            
            # Filtre bio_id
            if bio_id and log["bio_id"] != bio_id:
                continue
            
            filtered.append(log)
        
        return sorted(filtered, key=lambda x: x["timestamp"], reverse=True)
    
    def get_statistics(self, days=30):
        """
        Génère des statistiques d'audit
        
        Args:
            days: Nombre de jours à analyser
            
        Returns:
            dict: Statistiques
        """
        from datetime import timedelta
        
        start_date = datetime.now() - timedelta(days=days)
        logs = self.get_logs(start_date=start_date)
        
        stats = {
            "period_days": days,
            "total_events": len(logs),
            "by_type": {},
            "success_rate": 0,
            "failed_authentications": 0,
            "unique_bio_ids": set(),
            "security_alerts": 0
        }
        
        success_count = 0
        for log in logs:
            # Par type
            event_type = log["event_type"]
            stats["by_type"][event_type] = stats["by_type"].get(event_type, 0) + 1
            
            # Succès
            if log["success"]:
                success_count += 1
            
            # Auth échouées
            if event_type == "failed_authentication":
                stats["failed_authentications"] += 1
            
            # Alertes sécurité
            if event_type == "security_alert":
                stats["security_alerts"] += 1
            
            # IDs uniques
            if log["bio_id"]:
                stats["unique_bio_ids"].add(log["bio_id"])
        
        stats["unique_bio_ids"] = len(stats["unique_bio_ids"])
        stats["success_rate"] = (success_count / len(logs) * 100) if logs else 0
        
        return stats


# Test du module
if __name__ == "__main__":
    print("=== Test du module d'audit ===")
    
    logger = AuditLogger()
    
    # Test événements
    logger.log_enrollment("operator_001", "BIO-12345678-ABCD", ["face", "fingerprint"])
    logger.log_verification("BIO-12345678-ABCD", True, {"face": 95.5, "fingerprint": 87.2})
    logger.log_verification("BIO-12345678-ABCD", False, {"face": 35.0})
    logger.log_identification("hash123", "BIO-12345678-ABCD", 92.0)
    
    # Statistiques
    stats = logger.get_statistics()
    print(f"\n[OK] Statistiques: {stats}")
