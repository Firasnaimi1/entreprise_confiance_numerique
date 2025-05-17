# TrustSecure - Services de Confiance Numérique

Une application Flask offrant une suite de services numériques de confiance, incluant signature électronique, horodatage, parapheur électronique, et plus.

## Fonctionnalités

- **Signature Électronique** : Signez numériquement vos documents en toute sécurité
- **Horodatage Qualifié** : Prouvez l'existence d'un document à une date certaine
- **Parapheur Électronique** : Optimisez le processus de signature multi-parties
- **Coffre-Fort Numérique** : Stockez vos documents importants en toute sécurité
- **Vérification de Signature** : Vérifiez l'authenticité des documents signés
- **Gestion de Certificats** : Générez et gérez vos certificats numériques

## Installation

```bash
# Cloner le dépôt
git clone https://github.com/votre-username/trustsecure.git
cd trustsecure

# Créer un environnement virtuel
python -m venv venv
source venv/bin/activate  # Sur Windows: venv\Scripts\activate

# Installer les dépendances
pip install -r requirements.txt

# Initialiser la base de données
flask db init
flask db migrate -m "Initial migration"
flask db upgrade

# Lancer l'application
flask run
```

## Configuration

L'application utilise SQLite par défaut et génère une clé secrète à chaque démarrage.

En production, il est recommandé de configurer les variables suivantes dans un fichier `.env` :

```
SECRET_KEY=your-secret-key
DATABASE_URI=sqlite:///production.db
```

## Structure du Projet

- `app.py` : Application principale Flask
- `templates/` : Fichiers HTML pour le frontend
- `static/` : CSS, JavaScript et autres ressources statiques
- `signed_documents/` : Documents signés (générés par l'application)
- `signatory_documents/` : Documents du parapheur électronique
- `safe_documents/` : Documents stockés dans le coffre-fort numérique

## Sécurité

Cette application est conçue à des fins de démonstration. Pour un déploiement en production, il est recommandé de :

- Configurer HTTPS avec un certificat SSL valide
- Utiliser une base de données plus robuste comme PostgreSQL
- Implémenter une gestion des utilisateurs plus sécurisée
- Stocker les secrets dans des variables d'environnement

## Licence

MIT 