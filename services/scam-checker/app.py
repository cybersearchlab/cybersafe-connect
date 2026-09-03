"""
services/scam-checker/app.py
================================================================================
CyberSafe Connect Scam Checker Microservice
================================================================================

Point d'entrée du service, sur le modèle exact de services/auth/app.py.

Responsabilités :

    • Bootstrap de l'application FastAPI
    • Enregistrement des middlewares (CORS, limitation de débit)
    • Gestion globale des exceptions
    • Enregistrement des routes
    • Surveillance de l'état de santé (/health)
    • Initialisation au démarrage (création des tables)

Ce fichier NE DOIT PAS contenir de logique métier.

La logique métier appartient à :

    • routes.py
    • services.py

La logique de sécurité appartient à :

    • security.py
    • dependencies.py

================================================================================
"""

import sys
import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded
from sqlalchemy import text

from config import ALLOWED_ORIGINS
from database import Base, engine, SessionLocal
from limiter import limiter
from routes import router


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    stream=sys.stdout,
)

logger = logging.getLogger(__name__)


app = FastAPI(
    title="CyberSafe Connect - Scam Checker Service",
    version="1.0.0",
)

# Enregistre le limiteur de débit (limiter.py) sur l'état de l'application —
# requis par slowapi pour que les décorateurs @limiter.limit(...) de
# routes.py fonctionnent.
app.state.limiter = limiter


@app.on_event("startup")
def startup():
    # Crée les tables (blacklist_entries, whitelist_entries, scam_reports,
    # blacklist_audit_log) si elles n'existent pas encore — idempotent, sans
    # effet si elles sont déjà présentes.
    Base.metadata.create_all(bind=engine)
    logger.info("Scam Checker service started")


app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,

    allow_methods=[
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "OPTIONS",
    ],

    allow_headers=[
        "Authorization",
        "Content-Type",
    ],
)


@app.exception_handler(RateLimitExceeded)
def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    """
    Traduit le dépassement de débit détecté par slowapi vers le même format
    de réponse d'erreur que le reste de l'API (voir http_exception_handler
    ci-dessous), avec le code machine-readable RATE_LIMITED (proposition
    documentée dans CRL - CDC - Module 3 - 2.0.docx §13.2).
    """
    return JSONResponse(
        status_code=429,
        content={
            "success": False,
            "error": "Trop de requêtes, veuillez réessayer plus tard",
            "code": "RATE_LIMITED",
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Traduit les erreurs de validation Pydantic (422) vers le format explicitement
    exigé par le CDC (CRL-CDC-Module3-2.0 §6 : « En cas d'erreur de validation,
    l'API retourne { success: false, errors: {...} } ») — sans ce gestionnaire,
    FastAPI renvoie son format brut { detail: [...] }, qui ne respecte ni ce
    contrat ni celui des autres erreurs de ce service (voir
    http_exception_handler ci-dessous). Regroupe les erreurs par nom de champ
    (dernier élément de `loc`), plusieurs messages étant possibles pour un même
    champ.
    """
    errors: dict[str, list[str]] = {}
    for error in exc.errors():
        field = str(error["loc"][-1]) if error["loc"] else "body"
        errors.setdefault(field, []).append(error["msg"])

    return JSONResponse(
        status_code=422,
        content={
            "success": False,
            "errors": errors,
            "code": "VALIDATION_ERROR",
        },
        headers={"X-Error-Code": "VALIDATION_ERROR"},
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(
    request: Request,
    exc: HTTPException,
):
    """
    Gestionnaire d'erreurs global — garantit que toute erreur levée par
    services.py (via HTTPException) ressorte dans un format JSON uniforme
    {success, error, code}, avec le code également renvoyé dans l'en-tête
    X-Error-Code, exactement comme dans services/auth/app.py.
    """

    code = "ERROR"

    if exc.headers and "X-Error-Code" in exc.headers:
        code = exc.headers["X-Error-Code"]

    detail = exc.detail

    if isinstance(detail, dict):
        message = detail.get("message", "Unknown error")
    else:
        message = str(detail)

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": message,
            "code": code,
        },
    )


@app.get("/")
def root():

    return {
        "success": True,
        "message": "CyberSafe Scam Checker Service Running",
    }


@app.get("/health")
def health():
    """Vérifie la connexion à la base — utilisé par le healthcheck Docker en production."""

    db = SessionLocal()

    try:
        db.execute(text("SELECT 1"))

        return {
            "success": True,
            "service": "scam-checker",
            "status": "healthy",
            "database": "connected",
        }

    except Exception:

        return {
            "success": False,
            "service": "scam-checker",
            "status": "degraded",
            "database": "disconnected",
        }

    finally:
        db.close()


app.include_router(router)
