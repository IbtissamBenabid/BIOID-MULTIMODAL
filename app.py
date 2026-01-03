"""
Application Flask - API REST BioID Sécurisée
Système d'identification biométrique multimodal
Conforme RGPD / Loi 09-08
"""
from flask import Flask, render_template, request, jsonify, Response, g, redirect, url_for
from functools import wraps
import cv2
import numpy as np
import base64
import os
import sys
from datetime import datetime

# Ajouter le chemin du projet
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.face_capture import FaceCapture, compare_faces
from modules.fingerprint_processor import FingerprintProcessor, compare_fingerprints
from modules.bioid_generator import BioIDGenerator
from modules.security import SecurityManager, DataProtection
from modules.audit import AuditLogger, AuditEventType
from modules.rbac import RBACManager, Role, Permission, require_permission
from modules.metrics import BiometricMetrics
from modules.database import DatabaseManager
from modules.compliance import ComplianceManager
from modules.risk_assessment import RiskAssessment
from modules.use_case_repository import UseCaseRepository
from config import FACES_DIR, FINGERPRINTS_DIR, DATABASE_FILE

# Import optionnel voix
try:
    from modules.voice_processor import VoiceProcessor, VOICE_AVAILABLE
    # Définir compare_voices localement pour éviter les problèmes d'import
    def compare_voices(features1, features2, threshold=0.3):
        """Compare deux empreintes vocales"""
        if features1 is None or features2 is None:
            return False, 1.0
        distance = np.linalg.norm(np.array(features1) - np.array(features2))
        match = distance <= threshold
        return match, float(distance)
except ImportError:
    VOICE_AVAILABLE = False
    def compare_voices(f1, f2, threshold=0.3):
        return False, 1.0

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max
app.config['SECRET_KEY'] = os.urandom(32)

# Initialiser les composants
id_generator = BioIDGenerator(DATABASE_FILE)
security_manager = SecurityManager()
audit_logger = AuditLogger()
rbac_manager = RBACManager()
db_manager = DatabaseManager()
metrics = BiometricMetrics()

# Initialiser les nouveaux modules de conformité
compliance_manager = ComplianceManager()
risk_assessment = RiskAssessment()
use_case_repository = UseCaseRepository()

# Variable globale pour la caméra
camera = None


# =============================================================================
# MIDDLEWARE ET UTILITAIRES
# =============================================================================

def get_client_ip():
    """Récupère l'IP du client"""
    return request.headers.get('X-Forwarded-For', request.remote_addr)


def api_response(success, data=None, error=None, status_code=200):
    """Standardise les réponses API"""
    response = {
        "success": success,
        "timestamp": datetime.now().isoformat()
    }
    if data:
        response["data"] = data
    if error:
        response["error"] = error
    return jsonify(response), status_code


def require_auth(f):
    """Décorateur pour authentification par token JWT"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')

        if not auth_header or not auth_header.startswith('Bearer '):
            return api_response(False, error="Token manquant ou invalide", status_code=401)

        token = auth_header.split(' ')[1]
        payload = rbac_manager.verify_access_token(token)

        if not payload:
            return api_response(False, error="Token invalide ou expiré", status_code=401)

        g.current_user = payload['sub']
        g.current_role = payload['role']
        g.user_id = payload['user_id']
        return f(*args, **kwargs)
    return decorated


def require_permission(permission):
    """Décorateur pour vérifier les permissions"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(g, 'current_user'):
                return api_response(False, error="Non authentifié", status_code=401)
            if not rbac_manager.has_permission(g.current_role, permission):
                return api_response(False, error="Permission refusée", status_code=403)
            return f(*args, **kwargs)
        return decorated
    return decorator


# =============================================================================
# ROUTES D'AUTHENTIFICATION
# =============================================================================

@app.route('/login')
def login_page():
    """Page de connexion - authentication handled client-side"""
    return render_template('login.html')


@app.route('/setup')
def setup_page():
    """Page de configuration initiale"""
    return render_template('setup.html')


@app.route('/api/setup/check')
def api_setup_check():
    """Check if initial setup is needed"""
    try:
        needs_setup = rbac_manager.is_first_user()
        return jsonify({"needs_setup": needs_setup})
    except Exception as e:
        # If database error, assume setup is needed
        return jsonify({"needs_setup": True})


@app.route('/api/auth/login', methods=['POST'])
def api_login():
    """API de connexion avec JWT"""
    data = request.get_json()

    if not data:
        return api_response(False, error="Données manquantes", status_code=400)

    username = data.get('username', '')
    password = data.get('password', '')

    if not username or not password:
        return api_response(False, error="Nom d'utilisateur et mot de passe requis", status_code=400)

    # Authentifier via RBAC
    user = rbac_manager.authenticate_user(username, password)

    if user:
        # Créer les tokens JWT
        access_token, refresh_token = rbac_manager.create_tokens(user)

        # Mettre à jour la dernière connexion
        db_manager.update_last_login(user['id'])

        # Logger l'événement
        rbac_manager.log_audit_event(
            user_id=user['id'],
            action='LOGIN',
            details={"ip": get_client_ip(), "role": user['role']},
            ip_address=get_client_ip()
        )

        return api_response(True, data={
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "username": username,
            "role": user['role'],
            "permissions": db_manager.get_user_permissions(user['role'])
        })
    else:
        # Logger la tentative échouée
        return api_response(False, error="Identifiants invalides", status_code=401)


@app.route('/api/auth/logout', methods=['POST'])
@require_auth
def api_logout():
    """API de déconnexion"""
    # Invalidate refresh token
    with db_manager.get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("""
                UPDATE users
                SET refresh_token = NULL
                WHERE id = %s
            """, (g.user_id,))
            conn.commit()

    rbac_manager.log_audit_event(
        user_id=g.user_id,
        action='LOGOUT',
        details={"ip": get_client_ip()},
        ip_address=get_client_ip()
    )

    return api_response(True, data={"message": "Déconnexion réussie"})


@app.route('/api/auth/refresh', methods=['POST'])
def api_refresh_token():
    """Rafraîchir le token d'accès"""
    data = request.get_json()

    if not data or 'refresh_token' not in data:
        return api_response(False, error="Refresh token manquant", status_code=400)

    refresh_token = data['refresh_token']
    new_access_token = rbac_manager.refresh_access_token(refresh_token)

    if new_access_token:
        return api_response(True, data={
            "access_token": new_access_token,
            "token_type": "Bearer"
        })
    else:
        return api_response(False, error="Refresh token invalide", status_code=401)


@app.route('/api/setup', methods=['POST'])
def api_initial_setup():
    """Initial setup - create first admin user"""
    if not rbac_manager.is_first_user():
        return api_response(False, error="Configuration déjà effectuée", status_code=400)

    data = request.get_json()
    if not data:
        return api_response(False, error="Données manquantes", status_code=400)

    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password or len(password) < 8:
        return api_response(False, error="Nom d'utilisateur et mot de passe (min 8 caractères) requis", status_code=400)

    try:
        user_id = rbac_manager.create_user(username, password, 'admin')
        return api_response(True, data={
            "message": "Administrateur créé avec succès",
            "user_id": user_id
        })
    except Exception as e:
        return api_response(False, error=f"Erreur lors de la création: {str(e)}", status_code=500)


@app.route('/api/users', methods=['GET'])
@require_auth
@require_permission('admin:users')
def api_list_users():
    """List all users (admin only)"""
    try:
        users = rbac_manager.get_all_users()
        return api_response(True, data={"users": users})
    except Exception as e:
        return api_response(False, error=f"Erreur: {str(e)}", status_code=500)


@app.route('/api/users', methods=['POST'])
@require_auth
@require_permission('admin:users')
def api_create_user():
    """Create a new user (admin only)"""
    data = request.get_json()
    if not data:
        return api_response(False, error="Données manquantes", status_code=400)

    username = data.get('username', '').strip()
    password = data.get('password', '')
    role = data.get('role', '')

    if not username or not password or role not in ['admin', 'agent']:
        return api_response(False, error="Nom d'utilisateur, mot de passe et rôle valide requis", status_code=400)

    if len(password) < 8:
        return api_response(False, error="Le mot de passe doit contenir au moins 8 caractères", status_code=400)

    try:
        user_id = rbac_manager.create_user(username, password, role, g.user_id)
        return api_response(True, data={
            "message": "Utilisateur créé avec succès",
            "user_id": user_id
        })
    except Exception as e:
        return api_response(False, error=f"Erreur lors de la création: {str(e)}", status_code=500)


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@require_auth
@require_permission('admin:users')
def api_deactivate_user(user_id):
    """Deactivate a user (admin only)"""
    if user_id == g.user_id:
        return api_response(False, error="Impossible de se désactiver soi-même", status_code=400)

    try:
        rbac_manager.deactivate_user(user_id, g.user_id)
        return api_response(True, data={"message": "Utilisateur désactivé"})
    except Exception as e:
        return api_response(False, error=f"Erreur: {str(e)}", status_code=500)


@app.route('/api/auth/change-password', methods=['POST'])
@require_auth
def api_change_password():
    """Change current user's password"""
    data = request.get_json()
    if not data:
        return api_response(False, error="Données manquantes", status_code=400)

    old_password = data.get('old_password', '')
    new_password = data.get('new_password', '')

    if not old_password or not new_password or len(new_password) < 8:
        return api_response(False, error="Ancien et nouveau mot de passe (min 8 caractères) requis", status_code=400)

    try:
        success = rbac_manager.change_password(g.user_id, old_password, new_password)
        if success:
            return api_response(True, data={"message": "Mot de passe changé avec succès"})
        else:
            return api_response(False, error="Ancien mot de passe incorrect", status_code=400)
    except Exception as e:
        return api_response(False, error=f"Erreur: {str(e)}", status_code=500)


@app.route('/api/auth/me', methods=['GET'])
@require_auth
def api_current_user():
    """Récupère les infos de l'utilisateur connecté"""
    return api_response(True, data={
        "username": g.current_user,
        "role": g.current_role,
        "permissions": rbac_manager.get_permissions(g.current_role)
    })


@app.route('/api/auth/register', methods=['POST'])
@require_auth
def api_register_user():
    """Créer un nouvel utilisateur (admin seulement)"""
    if g.current_role != 'admin':
        return api_response(False, error="Permission refusée", status_code=403)
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'user')
    
    if not username or not password:
        return api_response(False, error="Données manquantes", status_code=400)
    
    success = rbac_manager.create_user(username, password, role)
    
    if success:
        audit_logger.log_event(
            event_type=AuditEventType.DATA_MODIFICATION,
            actor=g.current_user,
            details={"action": "create_user", "created_user": username, "role": role},
            ip_address=get_client_ip()
        )
        return api_response(True, data={"message": f"Utilisateur {username} créé"})
    else:
        return api_response(False, error="Échec création utilisateur", status_code=400)


def get_camera():
    """Obtenir l'instance de la caméra"""
    global camera
    if camera is None or not camera.isOpened():
        # Libérer si existe mais non fonctionnelle
        if camera is not None:
            camera.release()
        
        # Essayer différents indices de caméra
        for index in [0, 1, 2]:
            camera = cv2.VideoCapture(index, cv2.CAP_DSHOW)  # DirectShow pour Windows
            if camera.isOpened():
                # Configurer la caméra
                camera.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
                camera.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
                camera.set(cv2.CAP_PROP_FPS, 30)
                print(f"[OK] Caméra ouverte sur index {index}")
                break
        
        if not camera.isOpened():
            print("[ERREUR] Impossible d'ouvrir la caméra")
            return None
    
    return camera


def release_camera():
    """Libérer la caméra"""
    global camera
    if camera is not None:
        camera.release()
        camera = None


# =============================================================================
# ROUTES PAGES WEB
# =============================================================================

def check_auth():
    """Vérifie si l'utilisateur est authentifié (sans décorateur)"""
    # Check for JWT token
    auth = request.headers.get('Authorization')
    if auth and auth.startswith('Bearer '):
        token = auth.split(' ')[1]
        payload = rbac_manager.verify_access_token(token)
        if payload:
            return True, payload['sub']

    # Check localStorage via JavaScript (not directly accessible server-side)
    # This is mainly for API calls, web pages handle auth client-side

    return False, None


@app.route('/')
def index():
    """Page d'accueil - authentication handled client-side"""
    # For web pages, authentication is handled client-side with JWT tokens
    # Don't do server-side checks here as browsers don't send Authorization headers
    return render_template('index.html')


@app.route('/enroll')
def enroll_page():
    """Page d'enrôlement"""
    return render_template('enroll.html')


@app.route('/verify')
def verify_page():
    """Page de vérification"""
    return render_template('verify.html')


# =============================================================================
# API - CAPTURE BIOMÉTRIQUE
# =============================================================================

@app.route('/api/video_feed')
def video_feed():
    """Stream vidéo pour la capture faciale"""
    def generate():
        import face_recognition
        cam = get_camera()
        
        if cam is None:
            # Retourner une image d'erreur
            error_img = np.zeros((480, 640, 3), dtype=np.uint8)
            cv2.putText(error_img, "Camera not available", (150, 240), 
                       cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 255), 2)
            ret, buffer = cv2.imencode('.jpg', error_img)
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n')
            return
        
        while True:
            success, frame = cam.read()
            if not success:
                # Réessayer d'ouvrir la caméra
                cam = get_camera()
                if cam is None:
                    break
                continue
            
            frame = cv2.flip(frame, 1)
            rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            small_frame = cv2.resize(rgb_frame, (0, 0), fx=0.25, fy=0.25)
            
            try:
                face_locations = face_recognition.face_locations(small_frame, model="hog")
                
                for (top, right, bottom, left) in face_locations:
                    top *= 4
                    right *= 4
                    bottom *= 4
                    left *= 4
                    cv2.rectangle(frame, (left, top), (right, bottom), (0, 255, 0), 2)
            except Exception as e:
                print(f"[WARN] Face detection error: {e}")
            
            ret, buffer = cv2.imencode('.jpg', frame)
            frame_bytes = buffer.tobytes()
            
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')
    
    return Response(generate(), mimetype='multipart/x-mixed-replace; boundary=frame')


@app.route('/api/capture_face', methods=['POST'])
@require_auth
def capture_face():
    """Capture une image faciale et extrait l'encodage"""
    import face_recognition
    
    try:
        data = request.get_json()
        image_data = data.get('image')
        
        if not image_data:
            return api_response(False, error="Pas d'image reçue", status_code=400)
        
        image_data = image_data.split(',')[1]
        image_bytes = base64.b64decode(image_data)
        nparr = np.frombuffer(image_bytes, np.uint8)
        frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        face_locations = face_recognition.face_locations(rgb_frame, model="hog")
        
        if not face_locations:
            return api_response(False, error="Aucun visage détecté")
        
        face_encodings = face_recognition.face_encodings(rgb_frame, face_locations)
        
        if not face_encodings:
            return api_response(False, error="Impossible d'encoder le visage")
        
        encoding = face_encodings[0].tolist()
        
        return api_response(True, data={
            "encoding": encoding,
            "message": "Visage capturé avec succès"
        })
        
    except Exception as e:
        return api_response(False, error=str(e), status_code=500)


@app.route('/api/process_fingerprint', methods=['POST'])
@require_auth
def process_fingerprint():
    """Traite une image d'empreinte digitale"""
    try:
        if 'fingerprint' not in request.files:
            return api_response(False, error="Pas de fichier reçu", status_code=400)
        
        file = request.files['fingerprint']
        
        if file.filename == '':
            return api_response(False, error="Nom de fichier vide", status_code=400)
        
        image_bytes = file.read()
        
        processor = FingerprintProcessor()
        processor.load_from_bytes(image_bytes)
        processor.preprocess()
        processor.extract_minutiae()
        features = processor.extract_features()
        
        return api_response(True, data={
            "features": features.tolist(),
            "minutiae_count": len(processor.minutiae),
            "message": f"Empreinte traitée: {len(processor.minutiae)} minutiae détectées"
        })
        
    except Exception as e:
        return api_response(False, error=str(e), status_code=500)


@app.route('/api/process_voice', methods=['POST'])
@require_auth
def process_voice():
    """Traite un enregistrement vocal (format WAV)"""
    if not VOICE_AVAILABLE:
        return api_response(False, error="Module vocal non disponible", status_code=501)
    
    try:
        if 'voice' not in request.files:
            return api_response(False, error="Pas de fichier audio reçu", status_code=400)
        
        file = request.files['voice']
        audio_bytes = file.read()
        
        # Le frontend envoie maintenant du WAV directement
        processor = VoiceProcessor()
        processor.load_from_bytes(audio_bytes)
        processor.preprocess()
        features = processor.extract_features()
        
        return api_response(True, data={
            "features": features.tolist(),
            "dimensions": len(features),
            "message": "Audio traité avec succès"
        })
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return api_response(False, error=str(e), status_code=500)


# =============================================================================
# API - ENRÔLEMENT
# =============================================================================

@app.route('/api/register', methods=['POST'])
@require_auth
def register_beneficiary():
    """
    Enregistre un nouveau bénéficiaire
    Endpoint: POST /api/register
    """
    try:
        data = request.get_json()
        
        name = data.get('name')
        face_encoding = data.get('face_encoding')
        fingerprint_features = data.get('fingerprint_features')
        voice_features = data.get('voice_features')
        consent = data.get('consent', {})
        
        if not name:
            return api_response(False, error="Nom requis", status_code=400)
        
        if not face_encoding and not fingerprint_features and not voice_features:
            return api_response(False, error="Au moins une donnée biométrique requise", status_code=400)
        
        # Valider le consentement (RGPD)
        if not consent.get('consent_given'):
            return api_response(False, error="Consentement requis", status_code=400)
        
        # Convertir en numpy arrays
        face_enc = np.array(face_encoding) if face_encoding else None
        fp_feat = np.array(fingerprint_features) if fingerprint_features else None
        voice_feat = np.array(voice_features) if voice_features else None
        
        # Enregistrer
        beneficiary = id_generator.register_beneficiary(
            name=name,
            face_encoding=face_enc,
            fingerprint_features=fp_feat,
            metadata={
                "voice_features": voice_feat.tolist() if voice_feat is not None else None,
                "consent": consent,
                "consent_date": datetime.now().isoformat(),
                "enrolled_by": g.current_user
            }
        )
        
        # Audit
        modalities = []
        if face_encoding: modalities.append("face")
        if fingerprint_features: modalities.append("fingerprint")
        if voice_features: modalities.append("voice")
        
        audit_logger.log_enrollment(
            operator_id=g.current_user,
            bio_id=beneficiary["bio_id"],
            modalities=modalities,
            ip_address=get_client_ip()
        )
        
        return api_response(True, data={
            "bio_id": beneficiary["bio_id"],
            "name": beneficiary["name"],
            "registration_date": beneficiary["registration_date"],
            "modalities": modalities,
            "message": f"Bénéficiaire enregistré avec l'ID: {beneficiary['bio_id']}"
        })
        
    except Exception as e:
        return api_response(False, error=str(e), status_code=500)


# =============================================================================
# API - VÉRIFICATION (1:1)
# =============================================================================

@app.route('/api/verify', methods=['POST'])
@require_auth
def verify_identity():
    """
    Vérifie l'identité d'un bénéficiaire (authentification 1:1)
    Endpoint: POST /api/verify
    """
    try:
        id_generator.reload_database()
        
        data = request.get_json()
        
        bio_id = data.get('bio_id')
        face_encoding = data.get('face_encoding')
        fingerprint_features = data.get('fingerprint_features')
        voice_features = data.get('voice_features')
        
        if not bio_id:
            return api_response(False, error="ID biométrique requis", status_code=400)
        
        # Convertir en numpy arrays
        face_enc = np.array(face_encoding) if face_encoding else None
        fp_feat = np.array(fingerprint_features) if fingerprint_features else None
        voice_feat = np.array(voice_features) if voice_features else None
        
        # Vérifier (inclut maintenant la voix)
        result = id_generator.verify_identity(bio_id, face_enc, fp_feat, voice_feat)
        
        # Enregistrer pour métriques (si mode test)
        if data.get('record_metrics'):
            is_genuine = data.get('is_genuine', True)
            if result.get('face_distance'):
                metrics.record_verification(is_genuine, result['face_distance'], 'face')
            if result.get('fingerprint_distance'):
                metrics.record_verification(is_genuine, result['fingerprint_distance'], 'fingerprint')
        
        # Audit
        audit_logger.log_verification(
            bio_id=bio_id,
            success=result.get("verified", False),
            confidence={
                "face": result.get("face_confidence"),
                "fingerprint": result.get("fingerprint_confidence")
            },
            ip_address=get_client_ip()
        )
        
        response = {
            "success": True,
            "result": result
        }
        print(f"[DEBUG API] Response: {response}")
        
        return jsonify(response)
        
    except Exception as e:
        return api_response(False, error=str(e), status_code=500)


# =============================================================================
# API - IDENTIFICATION (1:N)
# =============================================================================

@app.route('/api/identify', methods=['POST'])
@require_auth
def identify_person():
    """
    Identifie une personne parmi tous les bénéficiaires (1:N)
    Endpoint: POST /api/identify
    """
    try:
        id_generator.reload_database()
        
        data = request.get_json()
        
        face_encoding = data.get('face_encoding')
        fingerprint_features = data.get('fingerprint_features')
        
        if not face_encoding and not fingerprint_features:
            return api_response(False, error="Au moins une donnée biométrique requise", status_code=400)
        
        face_enc = np.array(face_encoding) if face_encoding else None
        fp_feat = np.array(fingerprint_features) if fingerprint_features else None
        
        # Rechercher dans la base
        beneficiary = id_generator.find_by_biometrics(face_enc, fp_feat)
        
        # Audit
        query_hash = security_manager.hash_biometric(face_enc if face_enc is not None else fp_feat)[:12]
        audit_logger.log_identification(
            query_hash=query_hash,
            found_bio_id=beneficiary["bio_id"] if beneficiary else None,
            confidence=0,  # TODO: calculer
            ip_address=get_client_ip()
        )
        
        if beneficiary:
            return api_response(True, data={
                "found": True,
                "bio_id": beneficiary["bio_id"],
                "name": beneficiary["name"],
                "message": "Personne identifiée"
            })
        else:
            return api_response(True, data={
                "found": False,
                "message": "Aucune correspondance trouvée"
            })
        
    except Exception as e:
        return api_response(False, error=str(e), status_code=500)


# =============================================================================
# API - GESTION DES DONNÉES
# =============================================================================

@app.route('/api/beneficiaries')
@require_auth
def list_beneficiaries():
    """Liste tous les bénéficiaires"""
    id_generator.reload_database()
    beneficiaries = id_generator.get_all_beneficiaries()
    stats = id_generator.get_statistics()
    
    # Audit
    audit_logger.log_data_access(
        actor=g.current_user,
        bio_id=None,
        access_type="list_all",
        ip_address=get_client_ip()
    )
    
    return jsonify({
        "success": True,
        "beneficiaries": beneficiaries,
        "statistics": stats
    })


@app.route('/api/beneficiaries/<bio_id>', methods=['GET'])
@require_auth
def get_beneficiary(bio_id):
    """Récupère les informations d'un bénéficiaire"""
    id_generator.reload_database()
    beneficiary = id_generator.find_by_id(bio_id)
    
    if not beneficiary:
        return api_response(False, error="Bénéficiaire non trouvé", status_code=404)
    
    # Anonymiser les données biométriques
    safe_data = {
        "bio_id": beneficiary["bio_id"],
        "name": beneficiary["name"],
        "registration_date": beneficiary["registration_date"],
        "status": beneficiary["status"],
        "has_face": beneficiary.get("face_encoding") is not None,
        "has_fingerprint": beneficiary.get("fingerprint_features") is not None,
        "has_voice": beneficiary.get("metadata", {}).get("voice_features") is not None
    }
    
    # Audit
    audit_logger.log_data_access(
        actor=g.current_user,
        bio_id=bio_id,
        access_type="read",
        ip_address=get_client_ip()
    )
    
    return api_response(True, data=safe_data)


@app.route('/api/beneficiaries/<bio_id>', methods=['DELETE'])
@require_auth
def delete_beneficiary(bio_id):
    """
    Supprime un bénéficiaire (droit à l'effacement RGPD)
    Endpoint: DELETE /api/beneficiaries/<bio_id>
    """
    try:
        id_generator.reload_database()
        
        # Vérifier existence
        beneficiary = id_generator.find_by_id(bio_id)
        if not beneficiary:
            return api_response(False, error="Bénéficiaire non trouvé", status_code=404)
        
        # Supprimer
        id_generator.database["beneficiaries"] = [
            b for b in id_generator.database["beneficiaries"]
            if b["bio_id"] != bio_id
        ]
        id_generator._save_database()
        
        # Audit
        audit_logger.log_event(
            AuditEventType.DATA_DELETION,
            actor=g.current_user,
            bio_id=bio_id,
            details={"reason": "user_request"},
            ip_address=get_client_ip()
        )
        
        return api_response(True, data={
            "message": f"Bénéficiaire {bio_id} supprimé",
            "deleted_at": datetime.now().isoformat()
        })
        
    except Exception as e:
        return api_response(False, error=str(e), status_code=500)


# =============================================================================
# API - AUDIT ET MÉTRIQUES
# =============================================================================

@app.route('/api/audit/logs')
@require_auth
def get_audit_logs():
    """Récupère les logs d'audit"""
    days = request.args.get('days', 7, type=int)
    event_type = request.args.get('type')
    bio_id = request.args.get('bio_id')
    
    from datetime import timedelta
    start_date = datetime.now() - timedelta(days=days)
    
    logs = audit_logger.get_logs(
        start_date=start_date,
        event_type=event_type,
        bio_id=bio_id
    )
    
    return api_response(True, data={
        "logs": logs[:100],  # Limiter à 100
        "total": len(logs)
    })


@app.route('/api/audit/stats')
@require_auth
def get_audit_stats():
    """Récupère les statistiques d'audit"""
    days = request.args.get('days', 30, type=int)
    stats = audit_logger.get_statistics(days)
    
    return api_response(True, data=stats)


@app.route('/api/metrics')
@require_auth
def get_biometric_metrics():
    """Récupère les métriques biométriques (FAR, FRR, EER)"""
    report = metrics.generate_report()
    return api_response(True, data=report)


@app.route('/api/metrics/threshold-analysis')
@require_auth
def analyze_threshold():
    """Analyse des seuils"""
    modality = request.args.get('modality')
    analysis = metrics.analyze_thresholds(modality)
    return api_response(True, data=analysis)


# =============================================================================
# API - ADMINISTRATION
# =============================================================================

@app.route('/api/admin/users', methods=['GET'])
@require_auth
def list_users():
    """Liste les utilisateurs"""
    users = rbac_manager.list_users()
    return api_response(True, data={"users": users})


@app.route('/api/admin/users', methods=['POST'])
@require_auth
def create_user():
    """Crée un utilisateur"""
    data = request.get_json()
    
    success, message = rbac_manager.create_user(
        username=data.get('username'),
        password=data.get('password'),
        role=data.get('role', 'user'),
        created_by=g.current_user
    )
    
    if success:
        return api_response(True, data={"message": message})
    else:
        return api_response(False, error=message, status_code=400)


@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return api_response(True, data={
        "status": "healthy",
        "version": "2.0.0",
        "modules": {
            "face": True,
            "fingerprint": True,
            "voice": VOICE_AVAILABLE,
            "security": True,
            "audit": True
        }
    })


# =============================================================================
# MÉTRIQUES BIOMÉTRIQUES
# =============================================================================

@app.route('/metrics')
def metrics_page():
    """Page des métriques biométriques"""
    return render_template('metrics.html')


@app.route('/api/metrics/report', methods=['GET'])
@require_auth
def get_metrics_report():
    """Génère un rapport complet des métriques"""
    try:
        report = metrics.generate_report()
        return api_response(True, data=report)
    except Exception as e:
        return api_response(False, error=str(e), status_code=500)


@app.route('/api/metrics/far_frr', methods=['GET'])
@require_auth
def get_far_frr():
    """Calcule FAR/FRR pour un seuil donné"""
    try:
        threshold = float(request.args.get('threshold', 0.5))
        modality = request.args.get('modality')
        
        far, frr = metrics.calculate_far_frr(threshold, modality)
        
        return api_response(True, data={
            "threshold": threshold,
            "modality": modality or "all",
            "far": far,
            "frr": frr
        })
    except Exception as e:
        return api_response(False, error=str(e), status_code=500)


@app.route('/api/metrics/eer', methods=['GET'])
@require_auth
def get_eer():
    """Calcule l'EER"""
    try:
        modality = request.args.get('modality')
        eer, threshold = metrics.calculate_eer(modality)
        
        return api_response(True, data={
            "modality": modality or "all",
            "eer": eer,
            "optimal_threshold": threshold
        })
    except Exception as e:
        return api_response(False, error=str(e), status_code=500)


@app.route('/api/metrics/generate_test_data', methods=['POST'])
@require_auth
def generate_test_data():
    """Génère des données de test simulées pour les métriques"""
    try:
        # Générer des scores simulés pour démonstration
        np.random.seed(42)
        
        # Scores genuine (distributions centrées sur des valeurs basses)
        genuine_face_scores = np.random.normal(0.25, 0.08, 50).clip(0, 1)
        genuine_fp_scores = np.random.normal(0.15, 0.05, 50).clip(0, 1)
        genuine_voice_scores = np.random.normal(0.8, 0.3, 50).clip(0, 3)
        
        # Scores impostor (distributions centrées sur des valeurs hautes)
        impostor_face_scores = np.random.normal(0.65, 0.12, 50).clip(0, 1)
        impostor_fp_scores = np.random.normal(0.55, 0.15, 50).clip(0, 1)
        impostor_voice_scores = np.random.normal(2.5, 0.5, 50).clip(0, 5)
        
        # Enregistrer les scores
        for score in genuine_face_scores:
            metrics.record_verification(True, score, "face")
        for score in genuine_fp_scores:
            metrics.record_verification(True, score, "fingerprint")
        for score in genuine_voice_scores:
            metrics.record_verification(True, score, "voice")
            
        for score in impostor_face_scores:
            metrics.record_verification(False, score, "face")
        for score in impostor_fp_scores:
            metrics.record_verification(False, score, "fingerprint")
        for score in impostor_voice_scores:
            metrics.record_verification(False, score, "voice")
        
        return api_response(True, data={
            "message": "Données de test générées",
            "genuine_count": 150,
            "impostor_count": 150
        })
    except Exception as e:
        return api_response(False, error=str(e), status_code=500)


@app.route('/api/metrics/reset', methods=['POST'])
@require_auth
def reset_metrics():
    """Réinitialise les données de métriques"""
    try:
        metrics.results = {"genuine": [], "impostor": []}
        metrics._save_results()
        
        return api_response(True, data={"message": "Métriques réinitialisées"})
    except Exception as e:
        return api_response(False, error=str(e), status_code=500)


# =============================================================================
# API - CONFORMITÉ ET AUDIT
# =============================================================================

@app.route('/api/compliance/report', methods=['GET'])
@require_auth
def get_compliance_report():
    """
    Génère un rapport de conformité RGPD/Loi 09-08
    Endpoint: GET /api/compliance/report
    """
    try:
        # Vérifier les permissions (Admin ou Auditor)
        user = get_current_user()
        if not user or user.get('role') not in ['admin', 'agent']:
            return api_response(False, error="Permissions insuffisantes", status_code=403)

        report = compliance_manager.generate_gdpr_compliance_report()

        # Audit
        audit_logger.log_event(
            AuditEventType.DATA_ACCESS,
            user['username'],
            details={"report_type": "compliance", "scope": "full"}
        )

        return api_response(True, data=report)
    except Exception as e:
        return api_response(False, error=str(e), status_code=500)


@app.route('/api/compliance/consent/<bio_id>', methods=['POST'])
@require_auth
def record_consent(bio_id):
    """
    Enregistre le consentement d'un bénéficiaire
    Endpoint: POST /api/compliance/consent/<bio_id>
    """
    try:
        user = get_current_user()
        if not user:
            return api_response(False, error="Authentification requise", status_code=401)

        data = request.get_json()
        consent_id = compliance_manager.record_consent(bio_id, data)

        # Audit
        audit_logger.log_event(
            AuditEventType.CONSENT_GIVEN,
            user['username'],
            bio_id=bio_id,
            details={"consent_id": consent_id}
        )

        return api_response(True, data={"consent_id": consent_id})
    except Exception as e:
        return api_response(False, error=str(e), status_code=500)


@app.route('/api/compliance/consent/<bio_id>/withdraw', methods=['POST'])
@require_auth
def withdraw_consent(bio_id):
    """
    Retire le consentement d'un bénéficiaire
    Endpoint: POST /api/compliance/consent/<bio_id>/withdraw
    """
    try:
        user = get_current_user()
        if not user:
            return api_response(False, error="Authentification requise", status_code=401)

        data = request.get_json()
        reason = data.get('reason', 'Demande du bénéficiaire')

        success = compliance_manager.withdraw_consent(bio_id, reason)

        if success:
            # Audit
            audit_logger.log_event(
                AuditEventType.CONSENT_WITHDRAWN,
                user['username'],
                bio_id=bio_id,
                details={"reason": reason}
            )

            return api_response(True, data={"message": "Consentement retiré"})
        else:
            return api_response(False, error="Consentement non trouvé ou déjà retiré")
    except Exception as e:
        return api_response(False, error=str(e), status_code=500)


@app.route('/api/risk/assessment', methods=['GET'])
@require_auth
def get_risk_assessment():
    """
    Génère une évaluation des risques de sécurité
    Endpoint: GET /api/risk/assessment
    """
    try:
        user = get_current_user()
        if not user or user.get('role') != 'admin':
            return api_response(False, error="Accès administrateur requis", status_code=403)

        # Configuration système actuelle
        system_config = {
            "active_mitigations": [
                "encryption", "access_control", "audit_logging",
                "quality_check", "liveness_check", "rbac"
            ],
            "modalities": ["face", "fingerprint", "voice"],
            "encryption": "AES-256"
        }

        # Résultats des tests pour analyse des biais
        test_results = {
            "demographic_data": {
                "gender": {
                    "male": [0.2, 0.25, 0.18, 0.22, 0.19],
                    "female": [0.21, 0.26, 0.20, 0.23, 0.18]
                },
                "age": {
                    "young": [0.19, 0.22, 0.17, 0.21, 0.18],
                    "elderly": [0.24, 0.28, 0.25, 0.26, 0.23]
                }
            }
        }

        assessment = risk_assessment.generate_security_audit_report(system_config, test_results)

        # Audit
        audit_logger.log_event(
            AuditEventType.SECURITY_ALERT,
            user['username'],
            details={"assessment_type": "security_audit"}
        )

        return api_response(True, data=assessment)
    except Exception as e:
        return api_response(False, error=str(e), status_code=500)


@app.route('/api/risk/simulation', methods=['POST'])
@require_auth
def simulate_attack():
    """
    Simule un scénario d'attaque pour évaluation
    Endpoint: POST /api/risk/simulation
    """
    try:
        user = get_current_user()
        if not user or user.get('role') != 'admin':
            return api_response(False, error="Accès administrateur requis", status_code=403)

        data = request.get_json()
        attack_type = data.get('attack_type', 'spoofing')
        modality = data.get('modality', 'face')
        difficulty = data.get('difficulty', 'medium')

        # Convertir en enum
        from modules.risk_assessment import AttackType
        try:
            attack_enum = AttackType(attack_type.upper())
        except ValueError:
            return api_response(False, error="Type d'attaque invalide", status_code=400)

        simulation = risk_assessment.simulate_attack_scenario(
            attack_enum, modality, difficulty
        )

        # Audit
        audit_logger.log_event(
            AuditEventType.SECURITY_ALERT,
            user['username'],
            details={
                "simulation_type": "attack_scenario",
                "attack_type": attack_type,
                "modality": modality
            }
        )

        return api_response(True, data=simulation)
    except Exception as e:
        return api_response(False, error=str(e), status_code=500)


@app.route('/api/usecases', methods=['GET'])
@require_auth
def get_use_cases():
    """
    Récupère la documentation des cas d'usage
    Endpoint: GET /api/usecases
    """
    try:
        user = get_current_user()
        if not user:
            return api_response(False, error="Authentification requise", status_code=401)

        documentation = use_case_repository.export_use_case_documentation()

        # Audit
        audit_logger.log_event(
            AuditEventType.DATA_ACCESS,
            user['username'],
            details={"access_type": "use_case_documentation"}
        )

        return api_response(True, data=documentation)
    except Exception as e:
        return api_response(False, error=str(e), status_code=500)


@app.route('/api/usecases/<use_case_id>', methods=['GET'])
@require_auth
def get_use_case(use_case_id):
    """
    Récupère un cas d'usage spécifique
    Endpoint: GET /api/usecases/<use_case_id>
    """
    try:
        user = get_current_user()
        if not user:
            return api_response(False, error="Authentification requise", status_code=401)

        use_case = use_case_repository.get_use_case(use_case_id)
        if not use_case:
            return api_response(False, error="Cas d'usage non trouvé", status_code=404)

        # Convertir en dict pour la réponse JSON
        use_case_data = {
            "id": use_case.id,
            "name": use_case.name,
            "description": use_case.description,
            "primary_actor": use_case.primary_actor.value,
            "secondary_actors": [actor.value for actor in use_case.secondary_actors],
            "preconditions": use_case.preconditions,
            "postconditions": use_case.postconditions,
            "main_flow": use_case.main_flow,
            "alternative_flows": use_case.alternative_flows,
            "exceptions": use_case.exceptions
        }

        return api_response(True, data=use_case_data)
    except Exception as e:
        return api_response(False, error=str(e), status_code=500)


@app.route('/api/metrics/bias-analysis', methods=['GET'])
@require_auth
def get_bias_analysis():
    """
    Génère une analyse complète des biais
    Endpoint: GET /api/metrics/bias-analysis
    """
    try:
        user = get_current_user()
        if not user or user.get('role') not in ['admin', 'agent']:
            return api_response(False, error="Permissions insuffisantes", status_code=403)

        # Données démographiques simulées (en production, utiliser des données réelles)
        demographic_data = {
            "gender": {
                "male": [0.2, 0.25, 0.18, 0.22, 0.19, 0.21, 0.23],
                "female": [0.21, 0.26, 0.20, 0.23, 0.18, 0.24, 0.19]
            },
            "age": {
                "young": [0.19, 0.22, 0.17, 0.21, 0.18, 0.20, 0.16],
                "elderly": [0.24, 0.28, 0.25, 0.26, 0.23, 0.27, 0.22]
            },
            "ethnicity": {
                "group_a": [0.20, 0.23, 0.19, 0.21, 0.18],
                "group_b": [0.22, 0.25, 0.21, 0.24, 0.20]
            }
        }

        bias_report = metrics.generate_bias_report(demographic_data)

        # Audit
        audit_logger.log_event(
            AuditEventType.DATA_ACCESS,
            user['username'],
            details={"report_type": "bias_analysis"}
        )

        return api_response(True, data=bias_report)
    except Exception as e:
        return api_response(False, error=str(e), status_code=500)


@app.route('/api/metrics/fairness/<float:threshold>', methods=['GET'])
@require_auth
def get_fairness_analysis(threshold):
    """
    Analyse l'équité pour un seuil donné
    Endpoint: GET /api/metrics/fairness/<threshold>
    """
    try:
        user = get_current_user()
        if not user or user.get('role') not in ['admin', 'agent']:
            return api_response(False, error="Permissions insuffisantes", status_code=403)

        demographic_data = {
            "gender": {
                "male": [0.2, 0.25, 0.18, 0.22, 0.19],
                "female": [0.21, 0.26, 0.20, 0.23, 0.18]
            },
            "age": {
                "young": [0.19, 0.22, 0.17, 0.21, 0.18],
                "elderly": [0.24, 0.28, 0.25, 0.26, 0.23]
            }
        }

        fairness_analysis = metrics.analyze_fairness_constraints(threshold, demographic_data)

        return api_response(True, data=fairness_analysis)
    except Exception as e:
        return api_response(False, error=str(e), status_code=500)


# =============================================================================
# MAIN
# =============================================================================

if __name__ == '__main__':
    print("=" * 60)
    print("   BioID - Système d'Identification Biométrique Sécurisé")
    print("   Version 2.0 - Conforme RGPD / Loi 09-08")
    print("=" * 60)
    print("\n[INFO] Modules chargés:")
    print("  ✓ Reconnaissance faciale")
    print("  ✓ Empreintes digitales")
    print(f"  {'✓' if VOICE_AVAILABLE else '✗'} Reconnaissance vocale")
    print("  ✓ Chiffrement des descripteurs")
    print("  ✓ Audit et traçabilité")
    print("  ✓ Gestion des rôles (RBAC)")
    print("  ✓ Métriques biométriques")
    print("  ✓ Conformité RGPD/Loi 09-08")
    print("  ✓ Évaluation des risques")
    print("  ✓ Documentation des cas d'usage")
    print("  ✓ Analyse des biais et équité")
    print("\n[INFO] Démarrage du serveur...")
    print("[INFO] Accédez à http://localhost:5000")
    print("[INFO] API Documentation: http://localhost:5000/api/health")
    print("[INFO] Appuyez sur Ctrl+C pour arrêter\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
