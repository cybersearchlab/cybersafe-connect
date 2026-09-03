"""
services/scam-checker/config.py
================================================================================
Configuration — Module Scam Checker (CyberSafe Connect)
================================================================================

Centralise toutes les valeurs configurables du service : connexion base de
données, secret JWT, origines CORS autorisées, et — spécifique à ce module —
les seuils du barème de scoring et les limites de débit.

Sur le modèle de services/auth/config.py : toute valeur lue depuis une
variable d'environnement a une valeur par défaut sûre pour le développement
local, à ne jamais utiliser telle quelle en production.

--------------------------------------------------------------------------------
POURQUOI CES VALEURS SONT ICI ET NULLE PART AILLEURS
--------------------------------------------------------------------------------
Le barème de points (rules.py, url_analyzer.py) et les seuils de décision
(ROUGE/ORANGE/VERT) sont volontairement séparés du code qui les applique.
Changer le seuil ROUGE de 70 à 75, ou le nombre de signalements nécessaires
pour confirmer une entrée, se fait en modifiant une seule ligne ici — sans
toucher à la logique métier de services.py.
================================================================================
"""

import os
from dotenv import load_dotenv

load_dotenv()

# =============================================================================
# ENVIRONNEMENT
# =============================================================================
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
PORT = int(os.getenv("PORT", "8002"))

# =============================================================================
# BASE DE DONNEES
# =============================================================================
# SQLite en développement (fichier local), PostgreSQL en production — la bascule
# se fait uniquement via la valeur de DATABASE_URL, sans changer le code.
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/scam_checker.db")

# =============================================================================
# JWT — VALIDATION UNIQUEMENT, PAS D'EMISSION
# =============================================================================
# Ce service n'émet jamais de token : il ne fait que vérifier ceux émis par le
# module auth. JWT_SECRET_KEY et JWT_ALGORITHM DOIVENT donc avoir exactement
# la même valeur que dans services/auth/.env, sans quoi toute vérification de
# token échouera (signature invalide).
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-secret-change-in-production")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

# Émetteur attendu dans le payload du token — doit correspondre à la constante
# JWT_ISSUER codée en dur dans services/auth/security.py.
JWT_ISSUER = "cybersafe-auth"

# =============================================================================
# CORS
# =============================================================================
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "ALLOWED_ORIGINS",
        "http://localhost:3000,http://localhost:3001",
    ).split(",")
    if origin.strip()
]

# =============================================================================
# BAREME DE SCORING
# =============================================================================
# Seuils de verdict (CRL-CDC-1.0 section 2, CRL-CDC-Module3-2.0 section 2/3.4) :
#
#     score >= SCORE_ROUGE_THRESHOLD          → ROUGE  (arnaque probable)
#     SCORE_ORANGE_THRESHOLD <= score < ...   → ORANGE (suspect)
#     score < SCORE_ORANGE_THRESHOLD          → VERT   (légitime)
#
# Ces valeurs de points n'étaient pas chiffrées dans les CDC sources — voir
# CRL - CDC - Module 3 - 2.0.docx §3.5 pour le détail du barème proposé et sa
# vérification contre les 3 exemples de référence du corpus de test.
SCORE_ROUGE_THRESHOLD = int(os.getenv("SCORE_ROUGE_THRESHOLD", "70"))
SCORE_ORANGE_THRESHOLD = int(os.getenv("SCORE_ORANGE_THRESHOLD", "30"))

# Score forcé quand un élément est trouvé confirmé en liste noire — un simple
# bonus additif ne suffirait pas à garantir ROUGE si le texte ne contient par
# ailleurs aucun indicateur (CRL-CDC-Module3-2.0 §3.2 : « suffit à lui seul »).
BLACKLIST_HIT_SCORE = 100

# =============================================================================
# SIGNALEMENT COMMUNAUTAIRE (methode 3)
# =============================================================================
# Anciennement : nombre de signalements indépendants nécessaires pour
# confirmer automatiquement une entrée. Retiré le 27/08/2026 — seul un
# administrateur confirme désormais une entrée (voir services.py,
# admin_confirm_entry) ; report_count sert uniquement à prioriser la revue.

# =============================================================================
# PRIORISATION DES SIGNALEMENTS PAR ETALEMENT TEMPOREL (benchmark 28/08/2026)
# =============================================================================
# Inspiré de PhishTank (seuil de confirmation communautaire) et de Community
# Notes (pondération par diversité plutôt que par volume brut) : un groupe de
# signalements arrivés en rafale (beaucoup de comptes distincts en très peu
# de temps) est un indice de coordination — plusieurs faux comptes créés pour
# faire blacklister une cible — plutôt qu'un consensus organique. Ce module
# n'a pas accès à des signaux de compte plus riches (ancienneté, IP...), les
# identités vivant dans le module auth ; l'étalement temporel des
# signalements déjà en base est le seul signal de diversité disponible sans
# appel réseau supplémentaire.
#
# Sert UNIQUEMENT à signaler/trier la file d'attente admin (GET
# /scam/admin/entries) — ne confirme, ne rejette, ni ne dépriorise jamais
# rien automatiquement (voir services.get_report_spread).
BURST_MIN_REPORTS = int(os.getenv("BURST_MIN_REPORTS", "3"))
BURST_WINDOW_MINUTES = float(os.getenv("BURST_WINDOW_MINUTES", "5"))

# =============================================================================
# LIMITATION DE DEBIT (anti-abus)
# =============================================================================
# Non chiffrée dans le CDC d'origine (« limité par IP/compte », sans valeur) —
# proposition documentée dans CRL - CDC - Module 3 - 2.0.docx §13.3.
RATE_LIMIT_CHECK = os.getenv("RATE_LIMIT_CHECK", "30/minute")
RATE_LIMIT_REPORT = os.getenv("RATE_LIMIT_REPORT", "10/minute")

# Taille maximale du texte accepté par /scam/check, pour empêcher l'envoi de
# payloads surdimensionnés (protection anti-abus complémentaire au rate limiting).
MAX_TEXT_LENGTH = int(os.getenv("MAX_TEXT_LENGTH", "2000"))

# =============================================================================
# PREUVES DE SIGNALEMENT (captures d'écran, documents)
# =============================================================================
# Stockage local sur disque (mêmes principes que la base SQLite de
# développement) — dossier monté en volume Docker (voir docker-compose*.yml)
# pour survivre au redémarrage du conteneur.
EVIDENCE_DIR = os.getenv("EVIDENCE_DIR", "./data/evidence")

# Liste blanche stricte de types MIME acceptés — un signalement n'a besoin
# que d'images (captures d'écran) ou de PDF ; aucun format exécutable.
ALLOWED_EVIDENCE_TYPES = {
    "image/png", "image/jpeg", "image/webp", "application/pdf",
}

MAX_EVIDENCE_SIZE_BYTES = int(os.getenv("MAX_EVIDENCE_SIZE_MB", "5")) * 1024 * 1024
MAX_EVIDENCE_PER_REPORT = int(os.getenv("MAX_EVIDENCE_PER_REPORT", "5"))
