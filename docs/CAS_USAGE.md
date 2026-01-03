# BioID - Documentation du Cas d'Usage

## Système d'Identification Biométrique Multimodal pour Programme d'Aide Sociale

---

## 1. Contexte et Objectif

### 1.1 Cas d'Usage: Distribution d'Aide Sociale

Le système BioID est conçu pour gérer l'identification biométrique des bénéficiaires d'un programme d'aide sociale (ex: RAMED, Tayssir, aide directe). L'objectif est de :

- **Éviter les fraudes** (double inscription, usurpation d'identité)
- **Garantir l'unicité** de chaque bénéficiaire
- **Faciliter la vérification** lors de la distribution de l'aide
- **Assurer la traçabilité** des opérations

### 1.2 Acteurs du Système

| Acteur | Rôle | Permissions |
|--------|------|-------------|
| **Administrateur** | Gestion globale du système | Toutes les permissions |
| **Opérateur d'enrôlement** | Inscription des bénéficiaires | Créer, lire, modifier les enregistrements |
| **Agent de distribution** | Vérification lors de la distribution | Vérifier l'identité uniquement |
| **Auditeur** | Contrôle et audit | Lecture seule, export audit |
| **Bénéficiaire** | Sujet du traitement | Droits RGPD (accès, rectification, suppression) |

---

## 2. Scénarios d'Utilisation

### 2.1 Scénario Normal - Enrôlement

```
1. Le bénéficiaire se présente avec sa pièce d'identité
2. L'opérateur vérifie l'identité civile
3. L'opérateur recueille le consentement explicite (formulaire signé)
4. Capture biométrique:
   - 10 photos du visage (angles variés)
   - Image de l'empreinte digitale (index droit)
   - [Optionnel] Enregistrement vocal (phrase de contrôle)
5. Le système génère un UUID unique
6. Les descripteurs sont chiffrés et stockés
7. Le bénéficiaire reçoit sa carte avec l'ID biométrique
```

### 2.2 Scénario Normal - Vérification (Distribution)

```
1. Le bénéficiaire présente sa carte avec l'ID
2. L'agent saisit l'ID ou scanne le QR code
3. Le système demande une capture biométrique
4. Comparaison 1:1 avec les données enregistrées
5. Si match: distribution autorisée + journalisation
6. Si échec: escalade vers superviseur
```

### 2.3 Scénario Normal - Identification (Recherche)

```
1. Un bénéficiaire a perdu sa carte
2. Capture biométrique du visage/empreinte
3. Recherche 1:N dans la base
4. Si trouvé: affichage de l'ID + vérification secondaire
5. Réémission de la carte si confirmé
```

### 2.4 Scénarios Dégradés

| Scénario | Action |
|----------|--------|
| **Caméra défaillante** | Utiliser empreinte seule (mode dégradé) |
| **Empreinte illisible** | Utiliser visage + vérification manuelle |
| **Serveur hors ligne** | Mode hors-ligne avec synchronisation différée |
| **Biométrie non reconnue** | Procédure d'exception avec superviseur |
| **Tentative de fraude détectée** | Alerte sécurité + blocage temporaire |

---

## 3. Analyse des Risques

### 3.1 Risques Biométriques

| Risque | Impact | Probabilité | Mitigation |
|--------|--------|-------------|------------|
| **Attaque par présentation (photo)** | Élevé | Moyen | Détection de vivacité (liveness) |
| **Attaque par empreinte synthétique** | Élevé | Faible | Capteurs multispectraux |
| **Usurpation par jumeau** | Moyen | Très faible | Fusion multimodale |
| **Dégradation des données** | Moyen | Moyen | Ré-enrôlement périodique |

### 3.2 Risques de Sécurité

| Risque | Impact | Mitigation |
|--------|--------|------------|
| **Vol de base de données** | Critique | Chiffrement AES-256 au repos |
| **Interception réseau** | Élevé | HTTPS/TLS 1.3 obligatoire |
| **Accès non autorisé** | Élevé | RBAC + authentification forte |
| **Injection SQL/Code** | Élevé | Validation des entrées + ORM |

### 3.3 Risques de Biais

| Type de Biais | Description | Mitigation |
|---------------|-------------|------------|
| **Biais ethnique** | Performance variable selon phototype | Données d'entraînement diversifiées |
| **Biais d'âge** | Enfants/personnes âgées moins reconnus | Seuils adaptatifs |
| **Biais de genre** | Performance asymétrique | Évaluation équitable |
| **Biais de handicap** | Empreintes endommagées | Modalités alternatives |

---

## 4. Contraintes Légales et Éthiques

### 4.1 Cadre Juridique - Loi 09-08 (Maroc)

La Loi n° 09-08 relative à la protection des personnes physiques à l'égard du traitement des données à caractère personnel s'applique:

- **Article 1**: Les données biométriques sont des données sensibles
- **Article 4**: Consentement préalable obligatoire
- **Article 7**: Autorisation CNDP requise pour traitement biométrique
- **Article 8**: Droit d'accès et de rectification
- **Article 12**: Durée de conservation limitée et justifiée

### 4.2 Conformité RGPD (si applicable)

| Principe | Application |
|----------|-------------|
| **Licéité** | Base légale: consentement explicite |
| **Limitation des finalités** | Identification pour aide sociale uniquement |
| **Minimisation** | Seuls descripteurs stockés (pas images brutes) |
| **Exactitude** | Mise à jour sur demande |
| **Limitation de conservation** | 5 ans après fin du programme |
| **Intégrité et confidentialité** | Chiffrement + contrôle d'accès |

### 4.3 Obligations Éthiques

1. **Transparence**: Information claire sur l'utilisation
2. **Proportionnalité**: Biométrie justifiée par le risque de fraude
3. **Non-discrimination**: Garantir l'accès à tous
4. **Révocabilité**: Possibilité de suppression des données
5. **Auditabilité**: Traçabilité complète des opérations

---

## 5. Architecture Technique

### 5.1 Vue d'Ensemble

```
┌─────────────────────────────────────────────────────────────┐
│                        FRONTEND                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │ Enroll   │  │ Verify   │  │  Admin   │  │  Audit   │    │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘    │
└───────┼─────────────┼─────────────┼─────────────┼──────────┘
        │             │             │             │
        └─────────────┴──────┬──────┴─────────────┘
                             │ HTTPS/TLS
┌────────────────────────────┴────────────────────────────────┐
│                      API REST (Flask)                        │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                   Auth Middleware                     │   │
│  │                  (JWT + RBAC)                         │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌──────────┐ │
│  │  Enroll    │ │  Verify    │ │  Identify  │ │  Audit   │ │
│  │  Module    │ │  Module    │ │  Module    │ │  Module  │ │
│  └─────┬──────┘ └─────┬──────┘ └─────┬──────┘ └────┬─────┘ │
└────────┼──────────────┼──────────────┼─────────────┼────────┘
         │              │              │             │
┌────────┴──────────────┴──────────────┴─────────────┴────────┐
│                    MODULES BIOMÉTRIQUES                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │  Face    │  │ Finger   │  │  Voice   │  │ Security │    │
│  │  Recog   │  │  Print   │  │  Recog   │  │ Manager  │    │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘    │
└───────┼─────────────┼─────────────┼─────────────┼──────────┘
        │             │             │             │
┌───────┴─────────────┴─────────────┴─────────────┴──────────┐
│                       STOCKAGE                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │ Descripteurs │  │    Audit     │  │    Keys      │       │
│  │  (chiffré)   │  │    Logs      │  │  (HSM/File)  │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
└─────────────────────────────────────────────────────────────┘
```

### 5.2 Séparation des Données

| Type | Stockage | Chiffrement | Rétention |
|------|----------|-------------|-----------|
| **Images brutes** | Non conservées | N/A | Supprimées après extraction |
| **Descripteurs biométriques** | JSON chiffré | AES-256 | 5 ans |
| **Métadonnées** | JSON | Non | 5 ans |
| **Logs d'audit** | Fichiers JSON | Non | 10 ans |
| **Clés de chiffrement** | Fichier séparé | Protection système | Indéfini |

---

## 6. API REST - Documentation

### 6.1 Endpoints Principaux

#### Enrôlement
```
POST /api/register
Body: {
  "name": "string",
  "face_encoding": [float],
  "fingerprint_features": [float],
  "voice_features": [float],  // optionnel
  "consent": {
    "consent_given": true,
    "consent_method": "signed_form"
  }
}
Response: {
  "success": true,
  "data": {
    "bio_id": "BIO-XXXXXXXX-XXXX",
    "name": "...",
    "modalities": ["face", "fingerprint"]
  }
}
```

#### Vérification (1:1)
```
POST /api/verify
Body: {
  "bio_id": "BIO-XXXXXXXX-XXXX",
  "face_encoding": [float],
  "fingerprint_features": [float]
}
Response: {
  "success": true,
  "result": {
    "verified": true,
    "face_match": true,
    "fingerprint_match": true,
    "face_confidence": 85.5,
    "fingerprint_confidence": 92.3
  }
}
```

#### Identification (1:N)
```
POST /api/identify
Body: {
  "face_encoding": [float]
}
Response: {
  "success": true,
  "data": {
    "found": true,
    "bio_id": "BIO-XXXXXXXX-XXXX",
    "name": "..."
  }
}
```

### 6.2 Codes d'Erreur

| Code | Signification |
|------|---------------|
| 400 | Requête invalide |
| 401 | Non authentifié |
| 403 | Permission refusée |
| 404 | Ressource non trouvée |
| 429 | Trop de requêtes |
| 500 | Erreur serveur |

---

## 7. Métriques et Évaluation

### 7.1 Métriques Biométriques

| Métrique | Définition | Valeur Cible |
|----------|------------|--------------|
| **FAR** (False Acceptance Rate) | % imposteurs acceptés | < 0.1% |
| **FRR** (False Rejection Rate) | % légitimes rejetés | < 1% |
| **EER** (Equal Error Rate) | Point FAR = FRR | < 1% |

### 7.2 Analyse des Seuils

```
Seuil 0.3 (strict):   FAR=0.01%, FRR=5%    → Haute sécurité
Seuil 0.5 (standard): FAR=0.5%,  FRR=2%    → Équilibré
Seuil 0.7 (permissif): FAR=2%,   FRR=0.5%  → Haute accessibilité
```

### 7.3 Tests Recommandés

1. **Test de performance**: 1000+ vérifications légitimes
2. **Test d'imposteur**: 1000+ tentatives d'usurpation
3. **Test de biais**: Évaluation par groupe démographique
4. **Test de robustesse**: Conditions variées (éclairage, angle)

---

## 8. Feuille de Route

### Phase 1 (Actuel)
- [x] Reconnaissance faciale (face_recognition)
- [x] Empreintes digitales (minutiae)
- [x] API REST basique
- [x] Audit et journalisation

### Phase 2 (À venir)
- [ ] Reconnaissance vocale (MFCC)
- [ ] Détection de vivacité (liveness)
- [ ] Interface d'administration
- [ ] Export RGPD automatisé

### Phase 3 (Évolutions)
- [ ] Intégration capteur d'empreinte USB
- [ ] Application mobile
- [ ] Haute disponibilité (clustering)
- [ ] Intégration HSM pour les clés

---

## 9. Références

- Loi n° 09-08 - Protection des données personnelles (Maroc)
- RGPD - Règlement Général sur la Protection des Données (UE)
- ISO/IEC 19795 - Biometric performance testing
- NIST SP 800-76 - Biometric Specifications

---

*Document généré le 03/01/2026 - BioID v2.0*
