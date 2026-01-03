"""
Application Flask - Interface Web BioID
Enrôlement et vérification biométrique
"""
from flask import Flask, render_template, request, jsonify, Response
import cv2
import numpy as np
import base64
import os
import sys

# Ajouter le chemin du projet
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.face_capture import FaceCapture, compare_faces
from modules.fingerprint_processor import FingerprintProcessor, compare_fingerprints
from modules.bioid_generator import BioIDGenerator
from config import FACES_DIR, FINGERPRINTS_DIR, DATABASE_FILE

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

# Initialiser le générateur d'ID
id_generator = BioIDGenerator(DATABASE_FILE)

# Variable globale pour la caméra
camera = None


def get_camera():
    """Obtenir l'instance de la caméra"""
    global camera
    if camera is None:
        camera = cv2.VideoCapture(0)
    return camera


def release_camera():
    """Libérer la caméra"""
    global camera
    if camera is not None:
        camera.release()
        camera = None


@app.route('/')
def index():
    """Page d'accueil"""
    return render_template('index.html')


@app.route('/enroll')
def enroll_page():
    """Page d'enrôlement"""
    return render_template('enroll.html')


@app.route('/verify')
def verify_page():
    """Page de vérification"""
    return render_template('verify.html')


@app.route('/api/video_feed')
def video_feed():
    """Stream vidéo pour la capture faciale"""
    def generate():
        import face_recognition
        cam = get_camera()
        
        while True:
            success, frame = cam.read()
            if not success:
                break
            
            # Miroir
            frame = cv2.flip(frame, 1)
            
            # Détection de visage
            rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            small_frame = cv2.resize(rgb_frame, (0, 0), fx=0.25, fy=0.25)
            face_locations = face_recognition.face_locations(small_frame, model="hog")
            
            # Dessiner les rectangles
            for (top, right, bottom, left) in face_locations:
                top *= 4
                right *= 4
                bottom *= 4
                left *= 4
                cv2.rectangle(frame, (left, top), (right, bottom), (0, 255, 0), 2)
            
            # Encoder en JPEG
            ret, buffer = cv2.imencode('.jpg', frame)
            frame_bytes = buffer.tobytes()
            
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')
    
    return Response(generate(), mimetype='multipart/x-mixed-replace; boundary=frame')


@app.route('/api/capture_face', methods=['POST'])
def capture_face():
    """Capture une image faciale et extrait l'encodage"""
    import face_recognition
    
    try:
        data = request.get_json()
        image_data = data.get('image')
        
        if not image_data:
            return jsonify({"success": False, "error": "Pas d'image reçue"})
        
        # Décoder l'image base64
        image_data = image_data.split(',')[1]
        image_bytes = base64.b64decode(image_data)
        nparr = np.frombuffer(image_bytes, np.uint8)
        frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        # Détecter et encoder le visage
        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        face_locations = face_recognition.face_locations(rgb_frame, model="hog")
        
        if not face_locations:
            return jsonify({"success": False, "error": "Aucun visage détecté"})
        
        face_encodings = face_recognition.face_encodings(rgb_frame, face_locations)
        
        if not face_encodings:
            return jsonify({"success": False, "error": "Impossible d'encoder le visage"})
        
        # Retourner l'encodage
        encoding = face_encodings[0].tolist()
        
        return jsonify({
            "success": True,
            "encoding": encoding,
            "message": "Visage capturé avec succès"
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route('/api/process_fingerprint', methods=['POST'])
def process_fingerprint():
    """Traite une image d'empreinte digitale"""
    try:
        if 'fingerprint' not in request.files:
            return jsonify({"success": False, "error": "Pas de fichier reçu"})
        
        file = request.files['fingerprint']
        
        if file.filename == '':
            return jsonify({"success": False, "error": "Nom de fichier vide"})
        
        # Lire l'image
        image_bytes = file.read()
        
        # Traiter l'empreinte
        processor = FingerprintProcessor()
        processor.load_from_bytes(image_bytes)
        processor.preprocess()
        processor.extract_minutiae()
        features = processor.extract_features()
        
        return jsonify({
            "success": True,
            "features": features.tolist(),
            "minutiae_count": len(processor.minutiae),
            "message": f"Empreinte traitée: {len(processor.minutiae)} minutiae détectées"
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route('/api/register', methods=['POST'])
def register_beneficiary():
    """Enregistre un nouveau bénéficiaire"""
    try:
        data = request.get_json()
        
        name = data.get('name')
        face_encoding = data.get('face_encoding')
        fingerprint_features = data.get('fingerprint_features')
        
        if not name:
            return jsonify({"success": False, "error": "Nom requis"})
        
        if not face_encoding and not fingerprint_features:
            return jsonify({"success": False, "error": "Au moins une donnée biométrique requise"})
        
        # Convertir en numpy arrays
        face_enc = np.array(face_encoding) if face_encoding else None
        fp_feat = np.array(fingerprint_features) if fingerprint_features else None
        
        # Enregistrer
        beneficiary = id_generator.register_beneficiary(
            name=name,
            face_encoding=face_enc,
            fingerprint_features=fp_feat
        )
        
        return jsonify({
            "success": True,
            "bio_id": beneficiary["bio_id"],
            "name": beneficiary["name"],
            "registration_date": beneficiary["registration_date"],
            "message": f"Bénéficiaire enregistré avec l'ID: {beneficiary['bio_id']}"
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route('/api/verify', methods=['POST'])
def verify_identity():
    """Vérifie l'identité d'un bénéficiaire"""
    try:
        # Recharger la base de données pour avoir les dernières données
        id_generator.reload_database()
        
        data = request.get_json()
        
        bio_id = data.get('bio_id')
        face_encoding = data.get('face_encoding')
        fingerprint_features = data.get('fingerprint_features')
        
        if not bio_id:
            return jsonify({"success": False, "error": "ID biométrique requis"})
        
        # Convertir en numpy arrays
        face_enc = np.array(face_encoding) if face_encoding else None
        fp_feat = np.array(fingerprint_features) if fingerprint_features else None
        
        # Vérifier
        result = id_generator.verify_identity(bio_id, face_enc, fp_feat)
        
        response = {
            "success": True,
            "result": result
        }
        print(f"[DEBUG API] Response: {response}")
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route('/api/beneficiaries')
def list_beneficiaries():
    """Liste tous les bénéficiaires"""
    id_generator.reload_database()
    beneficiaries = id_generator.get_all_beneficiaries()
    stats = id_generator.get_statistics()
    
    return jsonify({
        "success": True,
        "beneficiaries": beneficiaries,
        "statistics": stats
    })


@app.route('/api/search', methods=['POST'])
def search_by_biometrics():
    """Recherche un bénéficiaire par biométrie"""
    try:
        data = request.get_json()
        
        face_encoding = data.get('face_encoding')
        fingerprint_features = data.get('fingerprint_features')
        
        # Convertir en numpy arrays
        face_enc = np.array(face_encoding) if face_encoding else None
        fp_feat = np.array(fingerprint_features) if fingerprint_features else None
        
        # Rechercher
        beneficiary = id_generator.find_by_biometrics(face_enc, fp_feat)
        
        if beneficiary:
            return jsonify({
                "success": True,
                "found": True,
                "bio_id": beneficiary["bio_id"],
                "name": beneficiary["name"]
            })
        else:
            return jsonify({
                "success": True,
                "found": False,
                "message": "Aucun bénéficiaire correspondant"
            })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


if __name__ == '__main__':
    print("=" * 50)
    print("   BioID - Système d'Identification Biométrique")
    print("=" * 50)
    print("\n[INFO] Démarrage du serveur...")
    print("[INFO] Accédez à http://localhost:5000")
    print("[INFO] Appuyez sur Ctrl+C pour arrêter\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
