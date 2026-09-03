"""
services/scam-checker/database.py
================================================================================
Connexion base de données — Module Scam Checker (CyberSafe Connect)
================================================================================

Configure le moteur SQLAlchemy et la fabrique de sessions utilisés par tout
le service. Fichier volontairement identique à services/auth/database.py,
pour que les deux services se comportent de façon prévisible (même ORM, même
bascule SQLite/PostgreSQL).

--------------------------------------------------------------------------------
POURQUOI CE SERVICE A SA PROPRE BASE DE DONNEES
--------------------------------------------------------------------------------
Règle d'architecture du projet : chaque microservice est un conteneur Docker
indépendant, avec ses propres données. Le Scam Checker ne partage donc PAS la
base du module auth — il ne fait que valider les tokens JWT qu'auth a émis
(voir security.py), sans jamais interroger la base de auth directement.
================================================================================
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from config import DATABASE_URL

# -----------------------------------------------------------------------------
# OPTIONS DE CONNEXION SPECIFIQUES A SQLITE
#
# SQLite refuse par défaut le partage d'une connexion entre threads. FastAPI
# traite les requêtes sur un pool de threads : sans cette option, une erreur
# "SQLite objects created in a thread can only be used in that same thread"
# apparaîtrait dès la première requête concurrente. Sans effet sur PostgreSQL.
# -----------------------------------------------------------------------------
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, connect_args=connect_args)

# Fabrique de sessions — une session par requête HTTP, ouverte et fermée par
# dependencies.get_db(). autocommit/autoflush désactivés : chaque
# modification doit être explicitement validée par db.commit() dans
# services.py, pour garder le contrôle exact du moment où les données sont
# persistées (important pour le journal d'audit, qui doit rester cohérent
# avec l'action qu'il décrit).
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Classe de base dont héritent tous les modèles ORM de models.py — c'est elle
# que app.py utilise au démarrage pour créer les tables (Base.metadata.create_all).
Base = declarative_base()
