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
from config import FACES_DIR, FINGERPRINTS_DIR, DATABASE_FILE

# Import optionnel voix
try:
    from modules.voice_processor import VoiceProcessor, compare_voices, VOICE_AVAILABLE
except ImportError:
    VOICE_AVAILABLE = False

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max
app.config['SECRET_KEY'] = os.urandom(32)

# Initialiser les composants
id_generator = BioIDGenerator(DATABASE_FILE)
security_manager = SecurityManager()
audit_logger = AuditLogger()
rbac_manager = RBACManager()
metrics = BiometricMetrics()

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
    """Décorateur pour authentification par token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization')
        
        if auth and auth.startswith('Bearer '):
            token = auth.split(' ')[1]
            valid, username = security_manager.verify_token(token)
            
            if valid:
                g.current_user = username
                user = rbac_manager.users["users"].get(username, {})
                g.current_role = user.get("role", "user")
                return f(*args, **kwargs)
        
        # Vérifier aussi dans les cookies (pour les pages web)
        token = request.cookies.get('bioIdToken')
        if token:
            valid, username = security_manager.verify_token(token)
            if valid:
                g.current_user = username
                user = rbac_manager.users["users"].get(username, {})
                g.current_role = user.get("role", "user")
                return f(*args, **kwargs)
        
        # Mode développement: permettre sans auth pour certaines routes
        if request.endpoint in ['video_feed', 'capture_face', 'process_fingerprint']:
            g.current_user = "anonymous"
            g.current_role = "operator"
            return f(*args, **kwargs)
        
        return api_response(False, error="Non authentifié", status_code=401)
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
    """Page de connexion"""
    return render_template('login.html')


@app.route('/api/auth/login', methods=['POST'])
def api_login():
    """API de connexion"""
    data = request.get_json()
    
    if not data:
        return api_response(False, error="Données manquantes", status_code=400)
    
    username = data.get('username', '')
    password = data.get('password', '')
    
    if not username or not password:
        return api_response(False, error="Nom d'utilisateur et mot de passe requis", status_code=400)
    
    # Authentifier via RBAC
    success, role = rbac_manager.authenticate(username, password)
    
    if success:
        # Générer un token
        token = security_manager.generate_token(username)
        
        # Logger l'événement
        audit_logger.log_event(
            event_type=AuditEventType.LOGIN,
            actor=username,
            details={"ip": get_client_ip(), "role": role},
            ip_address=get_client_ip()
        )
        
        return api_response(True, data={
            "token": token,
            "username": username,
            "role": role,
            "permissions": rbac_manager.get_permissions(role)
        })
    else:
        # Logger la tentative échouée
        audit_logger.log_event(
            event_type=AuditEventType.FAILED_AUTH,
            actor=username,
            details={"reason": "Échec authentification", "ip": get_client_ip()},
            ip_address=get_client_ip(),
            success=False
        )
        
        return api_response(False, error="Identifiants invalides", status_code=401)


@app.route('/api/auth/logout', methods=['POST'])
@require_auth
def api_logout():
    """API de déconnexion"""
    audit_logger.log_event(
        event_type=AuditEventType.LOGOUT,
        actor=g.current_user,
        details={"ip": get_client_ip()},
        ip_address=get_client_ip()
    )
    
    return api_response(True, data={"message": "Déconnexion réussie"})


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
    # Vérifier le header Authorization
    auth = request.headers.get('Authorization')
    if auth and auth.startswith('Bearer '):
        token = auth.split(' ')[1]
        valid, username = security_manager.verify_token(token)
        if valid:
            return True, username
    
    # Vérifier le cookie
    token = request.cookies.get('bioIdToken')
    if token:
        valid, username = security_manager.verify_token(token)
        if valid:
            return True, username
    
    return False, None


@app.route('/')
def index():
    """Page d'accueil - redirige vers login si non authentifié"""
    is_auth, _ = check_auth()
    if not is_auth:
        return redirect(url_for('login_page'))
    return render_template('index.html')


@app.route('/enroll')
def enroll_page():
    """Page d'enrôlement - nécessite authentification"""
    is_auth, _ = check_auth()
    if not is_auth:
        return redirect(url_for('login_page'))
    return render_template('enroll.html')


@app.route('/verify')
def verify_page():
    """Page de vérification - nécessite authentification"""
    is_auth, _ = check_auth()
    if not is_auth:
        return redirect(url_for('login_page'))
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
    """Traite un enregistrement vocal"""
    if not VOICE_AVAILABLE:
        return api_response(False, error="Module vocal non disponible", status_code=501)
    
    try:
        if 'voice' not in request.files:
            return api_response(False, error="Pas de fichier audio reçu", status_code=400)
        
        file = request.files['voice']
        audio_bytes = file.read()
        
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
        
        # Vérifier
        result = id_generator.verify_identity(bio_id, face_enc, fp_feat)
        
        # TODO: Ajouter vérification vocale si disponible
        
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
    print("\n[INFO] Démarrage du serveur...")
    print("[INFO] Accédez à http://localhost:5000")
    print("[INFO] API Documentation: http://localhost:5000/api/health")
    print("[INFO] Appuyez sur Ctrl+C pour arrêter\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
