"""
Database module for PostgreSQL
Handles user authentication and data storage
"""
import psycopg2
from psycopg2.extras import RealDictCursor
import json
from datetime import datetime, timedelta
import jwt
import bcrypt
from config import DATABASE_URL, JWT_SECRET_KEY, JWT_ALGORITHM, JWT_ACCESS_TOKEN_EXPIRE_MINUTES, JWT_REFRESH_TOKEN_EXPIRE_DAYS


class DatabaseManager:
    """Manages PostgreSQL database connections and operations"""

    def __init__(self):
        self.connection_string = DATABASE_URL
        self._create_tables()

    def get_connection(self):
        """Get database connection"""
        return psycopg2.connect(self.connection_string)

    def _create_tables(self):
        """Create necessary tables if they don't exist"""
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                # Users table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(50) UNIQUE NOT NULL,
                        password_hash VARCHAR(255) NOT NULL,
                        role VARCHAR(20) NOT NULL CHECK (role IN ('admin', 'agent')),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        active BOOLEAN DEFAULT TRUE,
                        must_change_password BOOLEAN DEFAULT FALSE,
                        last_login TIMESTAMP NULL,
                        refresh_token VARCHAR(500) NULL
                    )
                """)

                # Beneficiaries table (for future use)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS beneficiaries (
                        id SERIAL PRIMARY KEY,
                        bio_id VARCHAR(36) UNIQUE NOT NULL,
                        name VARCHAR(255) NOT NULL,
                        registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        bio_hash VARCHAR(64),
                        face_encoding TEXT,
                        fingerprint_features TEXT,
                        voice_features TEXT,
                        metadata JSONB
                    )
                """)

                # Audit log table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS audit_log (
                        id SERIAL PRIMARY KEY,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        user_id INTEGER REFERENCES users(id),
                        action VARCHAR(100) NOT NULL,
                        resource VARCHAR(100),
                        details JSONB,
                        ip_address VARCHAR(45)
                    )
                """)

                conn.commit()

    def authenticate_user(self, username, password):
        """Authenticate user and return user data"""
        with self.get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT id, username, password_hash, role, active, must_change_password
                    FROM users
                    WHERE username = %s AND active = TRUE
                """, (username,))

                user = cursor.fetchone()
                if not user:
                    return None

                # Verify password
                if bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                    return dict(user)

                return None

    def create_user(self, username, password, role, created_by=None):
        """Create a new user"""
        if role not in ['admin', 'agent']:
            raise ValueError("Invalid role. Must be 'admin' or 'agent'")

        # Hash the password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO users (username, password_hash, role, must_change_password)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id
                """, (username, password_hash, role, False))

                user_id = cursor.fetchone()[0]
                conn.commit()

                # Log the user creation (only if created_by is not None)
                if created_by is not None:
                    self.log_audit_event(
                        user_id=created_by,
                        action='USER_CREATED',
                        resource=f'user:{user_id}',
                        details={'username': username, 'role': role}
                    )

                return user_id

    def change_password(self, user_id, old_password, new_password):
        """Change user password"""
        with self.get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                # Verify old password
                cursor.execute("""
                    SELECT password_hash FROM users WHERE id = %s
                """, (user_id,))

                user = cursor.fetchone()
                if not user or not bcrypt.checkpw(old_password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                    return False

                # Hash new password
                new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

                # Update password
                cursor.execute("""
                    UPDATE users
                    SET password_hash = %s, must_change_password = FALSE
                    WHERE id = %s
                """, (new_password_hash, user_id))

                conn.commit()
                return True

    def get_all_users(self):
        """Get all users (admin only)"""
        with self.get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT id, username, role, created_at, active, last_login
                    FROM users
                    ORDER BY created_at DESC
                """)
                return [dict(row) for row in cursor.fetchall()]

    def deactivate_user(self, user_id, deactivated_by):
        """Deactivate a user"""
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE users SET active = FALSE WHERE id = %s
                """, (user_id,))
                conn.commit()

                self.log_audit_event(
                    user_id=deactivated_by,
                    action='USER_DEACTIVATED',
                    resource=f'user:{user_id}'
                )

    def is_first_user(self):
        """Check if this is the first user (for initial setup)"""
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) FROM users")
                count = cursor.fetchone()[0]
                return count == 0

    def create_access_token(self, data: dict):
        """Create JWT access token"""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode.update({"exp": expire, "type": "access"})
        encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        return encoded_jwt

    def create_refresh_token(self, data: dict):
        """Create JWT refresh token"""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=JWT_REFRESH_TOKEN_EXPIRE_DAYS)
        to_encode.update({"exp": expire, "type": "refresh"})
        encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        return encoded_jwt

    def verify_token(self, token: str, token_type: str = "access"):
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            if payload.get("type") != token_type:
                return None
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.JWTError:
            return None

    def store_refresh_token(self, user_id: int, refresh_token: str):
        """Store refresh token for user"""
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE users
                    SET refresh_token = %s
                    WHERE id = %s
                """, (refresh_token, user_id))
                conn.commit()

    def get_user_by_refresh_token(self, refresh_token: str):
        """Get user by refresh token"""
        with self.get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT id, username, role
                    FROM users
                    WHERE refresh_token = %s AND active = TRUE
                """, (refresh_token,))
                return cursor.fetchone()

    def update_last_login(self, user_id: int):
        """Update user's last login timestamp"""
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE users
                    SET last_login = CURRENT_TIMESTAMP
                    WHERE id = %s
                """, (user_id,))
                conn.commit()

    def log_audit_event(self, user_id: int, action: str, resource: str = None, details: dict = None, ip_address: str = None):
        """Log audit event"""
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO audit_log (user_id, action, resource, details, ip_address)
                    VALUES (%s, %s, %s, %s, %s)
                """, (user_id, action, resource, json.dumps(details) if details else None, ip_address))
                conn.commit()

    def get_user_permissions(self, role: str):
        """Get permissions for a role"""
        # Define permissions for each role
        permissions = {
            'admin': [
                'enroll:create', 'enroll:read', 'enroll:update', 'enroll:delete',
                'verify:execute', 'identify:execute', 'data:read', 'data:export',
                'data:delete', 'audit:read', 'audit:export', 'admin:users',
                'admin:config', 'admin:keys'
            ],
            'agent': [
                'enroll:create', 'enroll:read', 'enroll:update', 'verify:execute',
                'identify:execute', 'data:read', 'audit:read'
            ]
        }
        return permissions.get(role, [])