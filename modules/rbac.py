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
from modules.database import DatabaseManager


class Role(Enum):
    """Rôles du système"""
    ADMIN = "admin"           # Administrateur système
    AGENT = "agent"           # Agent d'enrôlement et vérification


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

    Role.AGENT: [
        Permission.ENROLL_CREATE,
        Permission.ENROLL_READ,
        Permission.ENROLL_UPDATE,
        Permission.VERIFY_EXECUTE,
        Permission.IDENTIFY_EXECUTE,
        Permission.DATA_READ,
        Permission.AUDIT_READ,
    ]
}


class RBACManager:
    """Gère les rôles, utilisateurs et permissions"""

    def __init__(self):
        """
        Initialize RBAC Manager with database
        """
        self.db = DatabaseManager()

    def has_permission(self, role, permission):
        """
        Vérifie si un rôle a une permission

        Args:
            role: Rôle à vérifier
            permission: Permission à vérifier

        Returns:
            bool: True si le rôle a la permission
        """
        if isinstance(role, str):
            try:
                role = Role(role)
            except ValueError:
                return False

        if isinstance(permission, str):
            try:
                permission = Permission(permission)
            except ValueError:
                return False

        return permission in ROLE_PERMISSIONS.get(role, [])

    def get_user_permissions(self, username):
        """
        Récupère les permissions d'un utilisateur

        Args:
            username: Nom d'utilisateur

        Returns:
            list: Liste des permissions
        """
        # This would be called after authentication
        # For now, return permissions based on role from database
        # In practice, this should be cached or retrieved from JWT token
        return []

    def authenticate_user(self, username, password):
        """
        Authentifie un utilisateur

        Args:
            username: Nom d'utilisateur
            password: Mot de passe

        Returns:
            dict or None: Données utilisateur si authentifié
        """
        return self.db.authenticate_user(username, password)

    def create_tokens(self, user_data):
        """
        Crée les tokens JWT pour un utilisateur

        Args:
            user_data: Données de l'utilisateur

        Returns:
            tuple: (access_token, refresh_token)
        """
        token_data = {
            "sub": user_data["username"],
            "role": user_data["role"],
            "user_id": user_data["id"]
        }

        access_token = self.db.create_access_token(token_data)
        refresh_token = self.db.create_refresh_token(token_data)

        # Store refresh token
        self.db.store_refresh_token(user_data["id"], refresh_token)

        return access_token, refresh_token

    def verify_access_token(self, token):
        """
        Vérifie un token d'accès JWT

        Args:
            token: Token JWT

        Returns:
            dict or None: Payload du token si valide
        """
        return self.db.verify_token(token, "access")

    def verify_refresh_token(self, token):
        """
        Vérifie un token de rafraîchissement JWT

        Args:
            token: Token de rafraîchissement

        Returns:
            dict or None: Payload du token si valide
        """
        return self.db.verify_token(token, "refresh")

    def refresh_access_token(self, refresh_token):
        """
        Rafraîchit un token d'accès

        Args:
            refresh_token: Token de rafraîchissement

        Returns:
            str or None: Nouveau token d'accès
        """
        payload = self.verify_refresh_token(refresh_token)
        if not payload:
            return None

        # Verify refresh token exists in database
        user = self.db.get_user_by_refresh_token(refresh_token)
        if not user:
            return None

        # Create new access token
        token_data = {
            "sub": user["username"],
            "role": user["role"],
            "user_id": user["id"]
        }

        return self.db.create_access_token(token_data)

    def is_first_user(self):
        """Check if this is the first user (for initial setup)"""
        return self.db.is_first_user()

    def create_user(self, username, password, role, created_by=None):
        """Create a new user"""
        return self.db.create_user(username, password, role, created_by)

    def change_password(self, user_id, old_password, new_password):
        """Change user password"""
        return self.db.change_password(user_id, old_password, new_password)

    def get_all_users(self):
        """Get all users (admin only)"""
        return self.db.get_all_users()

    def get_permissions(self, role_str):
        """Retourne les permissions d'un rôle (par nom de rôle)"""
        try:
            role = Role(role_str)
            return [p.value for p in ROLE_PERMISSIONS.get(role, [])]
        except ValueError:
            return []

    def log_audit_event(self, user_id, action, resource=None, details=None, ip_address=None):
        """
        Log an audit event

        Args:
            user_id: User ID
            action: Action performed
            resource: Resource affected
            details: Additional details
            ip_address: Client IP address
        """
        self.db.log_audit_event(user_id, action, resource, details, ip_address)


def require_permission(permission):
    """
    Décorateur pour vérifier les permissions sur les routes Flask

    Usage:
        @require_permission(Permission.ENROLL_CREATE)
        def create_enrollment():
            ...
    """
    def decorator(f):
        from flask import request, jsonify, g

        def decorated_function(*args, **kwargs):
            # Récupérer l'utilisateur depuis le contexte (à définir via middleware)
            username = getattr(g, 'current_user', None)

            if not username:
                return jsonify({"error": "Non authentifié"}), 401

            rbac = RBACManager()
            if not rbac.has_permission(g.current_role, permission):
                return jsonify({"error": "Permission refusée"}), 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator
