# 🐳 BioID - Guide de Déploiement Docker

## Prérequis

- Docker Desktop installé
- Docker Compose installé
- Git (optionnel, pour cloner le projet)

## Déploiement Rapide

### 1. Démarrage simple (recommandé pour tests)

```bash
# Construire et démarrer
docker-compose up --build

# Ou en arrière-plan
docker-compose up --build -d
```

L'application sera accessible sur **http://localhost:5000**

### 2. Démarrage avec HTTPS (production)

```bash
# Créer le dossier SSL
mkdir -p ssl

# Générer un certificat auto-signé (pour tests)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout ssl/key.pem -out ssl/cert.pem \
  -subj "/CN=bioid.local"

# Démarrer avec Nginx
docker-compose --profile with-nginx up --build -d
```

L'application sera accessible sur **https://localhost**

## Configuration

### Variables d'environnement

Créez un fichier `.env` à partir de `.env.example`:

```bash
cp .env.example .env
```

Modifiez les valeurs:

```env
JWT_SECRET_KEY=votre-cle-secrete-production
DATABASE_URL=postgres://user:pass@host:port/db?sslmode=require
```

### Volumes de données

Les données sont persistées dans des volumes Docker:
- `bioid-data`: Données biométriques, base de données
- `bioid-logs`: Logs de l'application

## Commandes Utiles

```bash
# Voir les logs
docker-compose logs -f bioid

# Redémarrer
docker-compose restart bioid

# Arrêter
docker-compose down

# Arrêter et supprimer les volumes (⚠️ perte de données)
docker-compose down -v

# Reconstruire sans cache
docker-compose build --no-cache

# Shell dans le conteneur
docker exec -it bioid-app bash

# Vérifier la santé
curl http://localhost:5000/api/health
```

## Partage avec Collaborateurs

### Option 1: Docker Hub

```bash
# Tag et push
docker tag bioid-app:latest votre-username/bioid:latest
docker push votre-username/bioid:latest

# Collaborateurs peuvent ensuite:
docker pull votre-username/bioid:latest
docker run -p 5000:5000 votre-username/bioid:latest
```

### Option 2: Export/Import

```bash
# Exporter l'image
docker save bioid-app:latest | gzip > bioid-app.tar.gz

# Importer (sur la machine du collaborateur)
gunzip -c bioid-app.tar.gz | docker load
docker run -p 5000:5000 bioid-app:latest
```

### Option 3: Partager le code source

Vos collaborateurs clonent le repo et exécutent:
```bash
docker-compose up --build
```

## Architecture

```
┌─────────────────────────────────────────────────┐
│                   Internet                       │
└─────────────────────┬───────────────────────────┘
                      │
          ┌───────────▼───────────┐
          │    Nginx (HTTPS)      │ Port 80/443
          │   - SSL termination   │
          │   - Rate limiting     │
          │   - Security headers  │
          └───────────┬───────────┘
                      │
          ┌───────────▼───────────┐
          │     BioID App         │ Port 5000
          │   - Flask + Gunicorn  │
          │   - Face recognition  │
          │   - Fingerprint       │
          │   - Voice (optional)  │
          └───────────┬───────────┘
                      │
          ┌───────────▼───────────┐
          │  PostgreSQL (Aiven)   │ Cloud
          │   - Users/Auth        │
          │   - Audit logs        │
          └───────────────────────┘
```

## Dépannage

### Erreur de build dlib

Si le build échoue sur dlib, augmentez les ressources Docker:
- Docker Desktop > Settings > Resources
- Augmentez Memory à 4GB minimum

### Erreur de connexion à la base de données

Vérifiez que l'URL PostgreSQL est correcte dans `.env` et que votre IP est autorisée sur Aiven.

### Port déjà utilisé

```bash
# Vérifier ce qui utilise le port 5000
netstat -ano | findstr :5000

# Ou changer le port dans docker-compose.yml
ports:
  - "8080:5000"
```

## Sécurité en Production

1. ⚠️ **Changez JWT_SECRET_KEY** - Utilisez une clé de 256 bits minimum
2. ⚠️ **Utilisez HTTPS** - Certificat Let's Encrypt ou autre CA
3. ⚠️ **Protégez les données** - Chiffrez les volumes Docker
4. ⚠️ **Mettez à jour régulièrement** - `docker-compose pull && docker-compose up -d`

## Support

En cas de problème, vérifiez les logs:
```bash
docker-compose logs bioid
```
