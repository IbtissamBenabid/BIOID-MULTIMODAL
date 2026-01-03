"""
Module de gestion des rôles et accès (RBAC)
Role-Based Access Control pour le système biométrique
"""
import json
import os
import hashlib
from datetime import datetime
from enum import Enum
from functools import wraps


class Role(Enum):
    """Rôles du système"""
    ADMIN = "admin"           # Administrateur système
    OPERATOR = "operator"     # Opérateur d'enrôlement
    AUDITOR = "auditor"       # Auditeur (lecture seule)
    USER = "user"             # Utilisateur standard
    SYSTEM = "system"         # Processus système


class Permission(Enum):
    """Permissions du système"""
    # Enrôlement
    ENROLL_CREATE = "enroll:create"
    ENROLL_READ = "enroll:read"
    ENROLL_UPDATE = "enroll:update"
    ENROLL_DELETE = "enroll:delete"
    
    # Vérification
    VERIFY_EXECUTE = "verify:execute"
    
    # Identification
    IDENTIFY_EXECUTE = "identify:execute"
    
    # Données
    DATA_READ = "data:read"
    DATA_EXPORT = "data:export"
    DATA_DELETE = "data:delete"
    
    # Audit
    AUDIT_READ = "audit:read"
    AUDIT_EXPORT = "audit:export"
    
    # Administration
    ADMIN_USERS = "admin:users"
    ADMIN_CONFIG = "admin:config"
    ADMIN_KEYS = "admin:keys"


# Matrice des permissions par rôle
ROLE_PERMISSIONS = {
    Role.ADMIN: [p for p in Permission],  # Toutes les permissions
    
    Role.OPERATOR: [
        Permission.ENROLL_CREATE,
        Permission.ENROLL_READ,
        Permission.ENROLL_UPDATE,
        Permission.VERIFY_EXECUTE,
        Permission.IDENTIFY_EXECUTE,
        Permission.DATA_READ,
    ],
    
    Role.AUDITOR: [
        Permission.ENROLL_READ,
        Permission.DATA_READ,
        Permission.AUDIT_READ,
        Permission.AUDIT_EXPORT,
    ],
    
    Role.USER: [
        Permission.VERIFY_EXECUTE,
    ],
    
    Role.SYSTEM: [
        Permission.VERIFY_EXECUTE,
        Permission.IDENTIFY_EXECUTE,
        Permission.AUDIT_READ,
    ]
}


class RBACManager:
    """Gère les rôles, utilisateurs et permissions"""
    
    def __init__(self, users_file="data/security/users.json"):
        """
        Args:
            users_file: Fichier de stockage des utilisateurs
        """
        self.users_file = users_file
        self.users = self._load_users()
    
    def _load_users(self):
        """Charge les utilisateurs depuis le fichier"""
        os.makedirs(os.path.dirname(self.users_file), exist_ok=True)
        
        if os.path.exists(self.users_file):
            with open(self.users_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        
        # Créer des utilisateurs par défaut
        default_users = {
            "users": {
                "admin": {
                    "password_hash": self._hash_password("admin123"),  # À changer!
                    "role": Role.ADMIN.value,
                    "created_at": datetime.now().isoformat(),
                    "active": True,
                    "must_change_password": True
                },
                "operator": {
                    "password_hash": self._hash_password("op123"),
                    "role": Role.OPERATOR.value,
                    "created_at": datetime.now().isoformat(),
                    "active": True,
                    "must_change_password": True
                },
                "auditor": {
                    "password_hash": self._hash_password("audit123"),
                    "role": Role.AUDITOR.value,
                    "created_at": datetime.now().isoformat(),
                    "active": True,
                    "must_change_password": True
                }
            }
        }
        self._save_users(default_users)
        print("[RBAC] Utilisateurs par défaut créés:")
        print("  - admin / admin123 (Admin)")
        print("  - operator / op123 (Opérateur)")
        print("  - auditor / audit123 (Auditeur)")
        
        return default_users
    
    def _save_users(self, users=None):
        """Sauvegarde les utilisateurs"""
        with open(self.users_file, 'w', encoding='utf-8') as f:
            json.dump(users or self.users, f, indent=2)
    
    def _hash_password(self, password):
        """Hash un mot de passe"""
        salt = "bioid_salt_v1"  # En production: salt unique par utilisateur
        return hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
    
    def create_user(self, username, password, role, created_by="system"):
        """
        Crée un nouvel utilisateur
        
        Args:
            username: Nom d'utilisateur
            password: Mot de passe
            role: Rôle (Role enum ou string)
            created_by: Utilisateur créateur
            
        Returns:
            bool: Succès
        """
        if username in self.users["users"]:
            return False
        
        role_value = role.value if isinstance(role, Role) else role
        
        self.users["users"][username] = {
            "password_hash": self._hash_password(password),
            "role": role_value,
            "created_at": datetime.now().isoformat(),
            "created_by": created_by,
            "active": True,
            "must_change_password": True
        }
        
        self._save_users()
        return True
    
    def authenticate(self, username, password):
        """
        Authentifie un utilisateur
        
        Args:
            username: Nom d'utilisateur
            password: Mot de passe
            
        Returns:
            tuple: (success: bool, role: str ou None)
        """
        user = self.users["users"].get(username)
        
        if not user:
            return False, None
        
        if not user["active"]:
            return False, None
        
        if self._hash_password(password) != user["password_hash"]:
            return False, None
        
        # Mettre à jour le dernier login
        user["last_login"] = datetime.now().isoformat()
        self._save_users()
        
        return True, user["role"]
    
    def check_permission(self, username, permission):
        """
        Vérifie si un utilisateur a une permission
        
        Args:
            username: Nom d'utilisateur
            permission: Permission à vérifier (Permission enum)
            
        Returns:
            bool: A la permission
        """
        user = self.users["users"].get(username)
        if not user or not user["active"]:
            return False
        
        role = Role(user["role"])
        role_perms = ROLE_PERMISSIONS.get(role, [])
        
        return permission in role_perms
    
    def get_user_permissions(self, username):
        """Retourne les permissions d'un utilisateur"""
        user = self.users["users"].get(username)
        if not user:
            return []
        
        role = Role(user["role"])
        return [p.value for p in ROLE_PERMISSIONS.get(role, [])]
    
    def get_permissions(self, role_str):
        """Retourne les permissions d'un rôle (par nom de rôle)"""
        try:
            role = Role(role_str)
            return [p.value for p in ROLE_PERMISSIONS.get(role, [])]
        except ValueError:
            return []
    
    def has_permission(self, role_str, permission_str):
        """
        Vérifie si un rôle a une permission spécifique
        
        Args:
            role_str: Nom du rôle (string)
            permission_str: Nom de la permission (string)
            
        Returns:
            bool: A la permission
        """
        try:
            role = Role(role_str)
            role_perms = ROLE_PERMISSIONS.get(role, [])
            
            # Chercher la permission par sa valeur
            for perm in role_perms:
                if perm.value == permission_str:
                    return True
            return False
        except ValueError:
            return False
    
    def change_password(self, username, old_password, new_password):
        """Change le mot de passe d'un utilisateur"""
        success, result = self.authenticate(username, old_password)
        if not success:
            return False, result
        
        self.users["users"][username]["password_hash"] = self._hash_password(new_password)
        self.users["users"][username]["must_change_password"] = False
        self._save_users()
        
        return True, "Mot de passe changé"
    
    def deactivate_user(self, username, deactivated_by):
        """Désactive un utilisateur"""
        if username not in self.users["users"]:
            return False, "Utilisateur non trouvé"
        
        self.users["users"][username]["active"] = False
        self.users["users"][username]["deactivated_at"] = datetime.now().isoformat()
        self.users["users"][username]["deactivated_by"] = deactivated_by
        self._save_users()
        
        return True, "Utilisateur désactivé"
    
    def list_users(self):
        """Liste tous les utilisateurs (sans mots de passe)"""
        return [
            {
                "username": username,
                "role": data["role"],
                "active": data["active"],
                "created_at": data["created_at"],
                "last_login": data.get("last_login")
            }
            for username, data in self.users["users"].items()
        ]


def require_permission(permission):
    """
    Décorateur pour vérifier les permissions sur les routes Flask
    
    Usage:
        @require_permission(Permission.ENROLL_CREATE)
        def create_enrollment():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask import request, jsonify, g
            
            # Récupérer l'utilisateur depuis le contexte (à définir via middleware)
            username = getattr(g, 'current_user', None)
            
            if not username:
                return jsonify({"error": "Non authentifié"}), 401
            
            rbac = RBACManager()
            if not rbac.check_permission(username, permission):
                return jsonify({"error": "Permission refusée"}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# Test du module
if __name__ == "__main__":
    print("=== Test du module RBAC ===")
    
    rbac = RBACManager()
    
    # Créer des utilisateurs de test
    rbac.create_user("operator1", "op123", Role.OPERATOR, "admin")
    rbac.create_user("auditor1", "audit123", Role.AUDITOR, "admin")
    
    # Test authentification
    success, result = rbac.authenticate("admin", "admin123")
    print(f"[OK] Auth admin: {success}, {result}")
    
    # Test permissions
    print(f"[OK] Admin peut créer enroll: {rbac.check_permission('admin', Permission.ENROLL_CREATE)}")
    print(f"[OK] Auditor peut créer enroll: {rbac.check_permission('auditor1', Permission.ENROLL_CREATE)}")
    print(f"[OK] Auditor peut lire audit: {rbac.check_permission('auditor1', Permission.AUDIT_READ)}")
    
    # Liste utilisateurs
    print(f"[OK] Utilisateurs: {rbac.list_users()}")
