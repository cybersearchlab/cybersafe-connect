"""
services/academy/security.py
===============================================================================
CyberSafe Connect Academy Security Layer
===============================================================================

JWT validation utilities for academy microservice.

Responsibilities
----------------

This module validates JWT access tokens issued by the authentication service.

Security responsibilities:

    • Verify JWT cryptographic signature
    • Verify token expiration
    • Verify issuer identity
    • Verify audience restriction
    • Verify token type
    • Extract authenticated user identity

Security Model
--------------

Academy DOES NOT authenticate users.

Academy TRUSTS tokens issued by auth service.

No direct database access to auth service is allowed.

Architecture:

    auth service
        ↓ issues signed JWT
    academy service
        ↓ validates JWT locally

===============================================================================
"""

import logging
from typing import Any

from jose import JWTError
from jose import ExpiredSignatureError
from jose import jwt

from config import (
    JWT_ALGORITHM,
    JWT_SECRET_KEY,
    JWT_ISSUER,
    JWT_AUDIENCE
)


# =============================================================================
# LOGGER
# =============================================================================

logger = logging.getLogger(__name__)


# =============================================================================
# SECURITY CONSTANTS
# =============================================================================

ACCESS_TOKEN_TYPE = "access"

MIN_SECRET_LENGTH = 64


# =============================================================================
# SECURITY CONFIGURATION VALIDATION
# =============================================================================

def validate_security_config() -> None:
    """
    Validate academy security configuration.

    Security checks:

        • Secret key presence
        • Secret strength validation

    Raises
    ------
    RuntimeError
        If security configuration is unsafe.
    """

    if not JWT_SECRET_KEY:
        raise RuntimeError(
            "JWT_SECRET_KEY missing"
        )

    if len(JWT_SECRET_KEY) < MIN_SECRET_LENGTH:
        raise RuntimeError(
            "JWT_SECRET_KEY too short"
        )


# =============================================================================
# ACCESS TOKEN VALIDATION
# =============================================================================

def decode_access_token(
    token: str
) -> dict[str, Any]:
    """
    Decode and validate JWT access token.

    Security checks:

        • Signature validation
        • Expiration validation
        • Issuer validation
        • Audience validation
        • Token type validation
        • Subject validation

    Parameters
    ----------
    token : str

    Returns
    -------
    dict

    Raises
    ------
    ValueError
        If token validation fails.
    """

    try:

        payload = jwt.decode(
            token,

            JWT_SECRET_KEY,

            algorithms=[JWT_ALGORITHM]
        )

    except ExpiredSignatureError as exc:

        logger.warning(
            "JWT expired"
        )

        raise ValueError(
            "Token expired"
        ) from exc

    except JWTError as exc:

        logger.warning(
            "JWT validation failed"
        )

        raise ValueError(
            "Invalid token"
        ) from exc


    # -------------------------------------------------------------------------
    # ISSUER VALIDATION
    # -------------------------------------------------------------------------

    if payload.get("iss") != JWT_ISSUER:

        logger.warning(
            "Invalid token issuer"
        )

        raise ValueError(
            "Invalid issuer"
        )


    # -------------------------------------------------------------------------
    # AUDIENCE VALIDATION
    # -------------------------------------------------------------------------

    if payload.get("aud") != JWT_AUDIENCE:

        logger.warning(
            "Invalid token audience"
        )

        raise ValueError(
            "Invalid audience"
        )


    # -------------------------------------------------------------------------
    # TOKEN TYPE VALIDATION
    # -------------------------------------------------------------------------

    if payload.get("type") != ACCESS_TOKEN_TYPE:

        logger.warning(
            "Invalid token type"
        )

        raise ValueError(
            "Invalid token type"
        )


    # -------------------------------------------------------------------------
    # SUBJECT VALIDATION
    # -------------------------------------------------------------------------

    if not payload.get("sub"):

        logger.warning(
            "Missing subject"
        )

        raise ValueError(
            "Invalid token payload"
        )


    return payload


# =============================================================================
# USER ID EXTRACTION
# =============================================================================

def extract_user_id(
    payload: dict[str, Any]
) -> int:
    """
    Extract authenticated user identifier.

    Parameters
    ----------
    payload : dict

    Returns
    -------
    int

    Raises
    ------
    ValueError
        If subject is invalid.
    """

    subject = payload.get("sub")

    if subject is None:
        raise ValueError(
            "Missing subject"
        )

    try:

        return int(subject)

    except (ValueError, TypeError) as exc:

        raise ValueError(
            "Invalid user identifier"
        ) from exc