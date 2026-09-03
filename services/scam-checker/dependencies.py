"""
services/scam-checker/dependencies.py
================================================================================
Dépendances FastAPI — Module Scam Checker (CyberSafe Connect)
================================================================================

Fonctions injectées automatiquement par FastAPI dans les routes (via
Depends(...)), sur le modèle de services/auth/dependencies.py. Elles gèrent
l'accès à la base de données et l'authentification, pour que routes.py n'ait
jamais à s'en préoccuper directement.

--------------------------------------------------------------------------------
NIVEAUX D'AUTHENTIFICATION DU MODULE
--------------------------------------------------------------------------------
Le CDC (CRL-CDC-Module3-2.0, section 7) distingue 3 niveaux d'accès, chacun
avec sa propre dépendance ci-dessous :

    get_current_user_optional     /scam/check — un citoyen non connecté peut
                                 vérifier un message, un citoyen connecté est
                                 identifié s'il l'est
    get_current_user             /scam/report, /scam/report/{id}/evidence — compte requis
    require_admin                 /scam/admin/*  — rôle admin requis en plus
                                 d'être connecté
================================================================================
"""

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from database import SessionLocal
from security import decode_access_token

# auto_error=False : ne lève pas d'exception si l'en-tête Authorization est
# absent — indispensable pour /scam/check, où la connexion est optionnelle.
bearer_scheme = HTTPBearer(auto_error=False)


# =============================================================================
# SESSION DE BASE DE DONNEES
# =============================================================================
def get_db():
    """
    Ouvre une session SQLAlchemy pour la durée d'une requête HTTP, la ferme
    systématiquement ensuite (bloc finally), même en cas d'erreur.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# =============================================================================
# UTILISATEUR COURANT — REPRESENTATION LEGERE
# =============================================================================
# Ce service n'a pas de table users locale (les comptes vivent dans le module
# auth) : CurrentUser reconstruit juste ce qu'il faut à partir du payload du
# token JWT (sub, email, role), sans requête base de données supplémentaire.
# =============================================================================
class CurrentUser:
    def __init__(self, user_id: int, email: str, role: str):
        self.user_id = user_id
        self.email = email
        self.role = role


# =============================================================================
# AUTHENTIFICATION OPTIONNELLE — /scam/check
# =============================================================================
def get_current_user_optional(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> CurrentUser | None:
    """
    Retourne l'utilisateur si un token valide est fourni, sinon None — ne lève
    jamais d'exception. Un token absent ou invalide n'empêche pas la
    vérification d'un message (critère d'acceptation : « un citoyen peut
    vérifier un texte ou une URL sans compte utilisateur »).
    """
    if credentials is None:
        return None
    try:
        payload = decode_access_token(credentials.credentials)
    except ValueError:
        return None
    return CurrentUser(
        user_id=int(payload["sub"]),
        email=payload.get("email", ""),
        role=payload.get("role", "citizen"),
    )


# =============================================================================
# AUTHENTIFICATION OBLIGATOIRE — /scam/report, /scam/report/{id}/evidence
# =============================================================================
def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> CurrentUser:
    """
    Comme get_current_user_optional, mais lève une erreur 401 explicite (avec
    code machine-readable X-Error-Code) si le token est absent ou invalide.
    """
    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"X-Error-Code": "AUTH_REQUIRED"},
        )
    try:
        payload = decode_access_token(credentials.credentials)
    except ValueError:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired access token",
            headers={"X-Error-Code": "INVALID_TOKEN"},
        )
    return CurrentUser(
        user_id=int(payload["sub"]),
        email=payload.get("email", ""),
        role=payload.get("role", "citizen"),
    )


# =============================================================================
# ROLE ADMINISTRATEUR — /scam/admin/*
# =============================================================================
def require_admin(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    """
    S'appuie sur get_current_user (donc exige déjà un compte valide), puis
    vérifie en plus que le rôle porté par le token est "admin". Le rôle
    provient du token émis par le module auth — ce service ne décide jamais
    lui-même qui est administrateur.
    """
    if current_user.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Administrator role required",
            headers={"X-Error-Code": "FORBIDDEN"},
        )
    return current_user
