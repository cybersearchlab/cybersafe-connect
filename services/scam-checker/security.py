"""
services/scam-checker/security.py
================================================================================
Vérification des tokens JWT — Module Scam Checker (CyberSafe Connect)
================================================================================

Contrairement à services/auth/security.py, ce module n'émet AUCUN token — le
Scam Checker n'a pas de système de connexion propre. Il se contente de
vérifier les tokens d'accès émis par le module auth, en réutilisant le même
secret et le même algorithme (JWT_SECRET_KEY / JWT_ALGORITHM, config.py).

--------------------------------------------------------------------------------
ROLE
--------------------------------------------------------------------------------
    • Décoder un token d'accès et vérifier sa signature
    • Rejeter un token expiré, mal signé, ou émis par un autre émetteur
    • Rejeter un refresh token présenté à la place d'un access token

--------------------------------------------------------------------------------
POURQUOI CA MARCHE SANS APPEL RESEAU VERS LE MODULE AUTH
--------------------------------------------------------------------------------
Un JWT est auto-suffisant : sa signature cryptographique prouve à elle seule
qu'il a été émis par un service possédant JWT_SECRET_KEY, sans avoir besoin
d'interroger ce service à chaque requête. C'est ce qui permet à un
microservice indépendant comme le Scam Checker de vérifier l'identité d'un
utilisateur sans dépendance réseau vers auth, et donc sans ralentir ni
fragiliser /scam/check si le module auth est temporairement indisponible.

================================================================================
"""

import logging
from typing import Any

from jose import JWTError, jwt

from config import JWT_ALGORITHM, JWT_ISSUER, JWT_SECRET_KEY

logger = logging.getLogger(__name__)


# =============================================================================
# DECODAGE ET VALIDATION D'UN ACCESS TOKEN
# =============================================================================
def decode_access_token(token: str) -> dict[str, Any]:
    """
    Décode un token d'accès émis par le module auth et vérifie son intégrité.

    Contrôles effectués, dans l'ordre :

        1. Signature cryptographique valide (JWT_SECRET_KEY / JWT_ALGORITHM)
        2. Non expiré (vérifié automatiquement par jose lors du décodage)
        3. Émetteur (iss) correspond bien au module auth
        4. Type de token = "access" (un refresh token est rejeté ici)
        5. Présence d'un sujet (sub) — l'identifiant de l'utilisateur

    Parameters
    ----------
    token : str
        Le token JWT brut, tel que fourni dans l'en-tête Authorization.

    Returns
    -------
    dict
        Le payload décodé (sub, email, role, ...).

    Raises
    ------
    ValueError
        Si le token est invalide, expiré, ou ne provient pas du module auth.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except JWTError as exc:
        logger.warning("Invalid JWT token presented to scam-checker")
        raise ValueError("Invalid or expired token") from exc

    if payload.get("iss") != JWT_ISSUER:
        raise ValueError("Invalid token issuer")

    if payload.get("type") != "access":
        raise ValueError("Invalid token type")

    if not payload.get("sub"):
        raise ValueError("Invalid token payload")

    return payload
