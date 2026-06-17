"""
modules/auth/security.py
================================================================================
Security Core Module – CyberSafe Connect Authentication Service
================================================================================

This module implements all cryptographic and authentication security mechanisms
used by the CyberSafe Connect authentication microservice.

It centralizes password security, JWT token generation, token validation,
cryptographic verification and authentication integrity controls.

--------------------------------------------------------------------------------
ROLE
--------------------------------------------------------------------------------

This module is responsible for:

    • Secure password hashing before database persistence
    • Password verification during authentication attempts
    • Access token generation (JWT)
    • Refresh token generation (JWT)
    • Token decoding and validation
    • Protection against malformed token attacks
    • Issuer verification
    • Token type validation
    • Preparation for future token revocation mechanisms

This module acts as the main cryptographic security layer of the authentication
service.

--------------------------------------------------------------------------------
SECURITY DESIGN PRINCIPLES
--------------------------------------------------------------------------------

Password Security:

    • Uses Argon2 hashing algorithm (recommended over bcrypt)
    • Passwords are never stored in plain text
    • Resistant against GPU brute-force attacks
    • Resistant against memory cracking attacks

JWT Security:

    • Separate access and refresh tokens
    • Strict token type validation
    • Unique token identifier (JTI)
    • Issuer verification
    • Expiration validation
    • Subject validation

Production Security:

    • Reject weak JWT secret keys
    • Reject malformed token payloads
    • Audit suspicious token decoding failures

--------------------------------------------------------------------------------
TOKEN STRUCTURE
--------------------------------------------------------------------------------

Access Token:

    {
        "sub": user_id
        "type": "access"
        "iat": issued_timestamp
        "exp": expiration_timestamp
        "jti": unique_token_id
        "iss": "cybersafe-auth"
    }

Refresh Token:

    {
        "sub": user_id
        "type": "refresh"
        "iat": issued_timestamp
        "exp": expiration_timestamp
        "jti": unique_token_id
        "iss": "cybersafe-auth"
    }

--------------------------------------------------------------------------------
DEPENDENCIES
--------------------------------------------------------------------------------

• python-jose
• passlib[argon2]
• uuid
• logging

Required package:

    pip install passlib[argon2]

================================================================================
"""

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from jose import JWTError, jwt
from passlib.context import CryptContext

from config import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    JWT_ALGORITHM,
    JWT_SECRET_KEY,
    REFRESH_TOKEN_EXPIRE_DAYS
)

from enums import TokenType


# =============================================================================
# SECURITY CONSTANTS
# =============================================================================

JWT_ISSUER = "cybersafe-auth"

MIN_SECRET_LENGTH = 64


# =============================================================================
# LOGGER
# =============================================================================

logger = logging.getLogger(__name__)


# =============================================================================
# SECRET KEY VALIDATION
# =============================================================================
# Prevent weak JWT secrets in production deployments.
# =============================================================================

if len(JWT_SECRET_KEY) < MIN_SECRET_LENGTH:
    raise RuntimeError(
        "JWT_SECRET_KEY is too short. Minimum 64 characters required."
    )


# =============================================================================
# PASSWORD HASHING CONFIGURATION
# =============================================================================
# Argon2 is recommended over bcrypt.
#
# Install:
#     pip install passlib[argon2]
# =============================================================================

pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto"
)


# =============================================================================
# PASSWORD VALIDATION
# =============================================================================

def _validate_password(password: str) -> None:
    """
    Internal password validation before hashing operations.

    Prevents malformed input and oversized payload attacks.

    Parameters
    ----------
    password : str

    Raises
    ------
    ValueError
        If password format is invalid.
    """

    if not isinstance(password, str):
        raise ValueError("Password must be a string")

    if len(password) > 128:
        raise ValueError("Password exceeds maximum allowed length")


# =============================================================================
# HASH PASSWORD
# =============================================================================

def hash_password(password: str) -> str:
    """
    Securely hash a user password using Argon2.

    Parameters
    ----------
    password : str

    Returns
    -------
    str
        Secure password hash.
    """

    _validate_password(password)

    return pwd_context.hash(password)


# =============================================================================
# VERIFY PASSWORD
# =============================================================================

def verify_password(
    plain_password: str,
    hashed_password: str
) -> bool:
    """
    Verify password against stored secure hash.

    Parameters
    ----------
    plain_password : str

    hashed_password : str

    Returns
    -------
    bool
        True if password is valid.
    """

    _validate_password(plain_password)

    return pwd_context.verify(
        plain_password,
        hashed_password
    )


# =============================================================================
# INTERNAL TOKEN GENERATOR
# =============================================================================

def _create_token(
    subject: str,
    token_type: TokenType,
    expires_delta: timedelta,
    extra: dict[str, Any] | None = None
) -> str:
    """
    Internal JWT token generation engine.
    """

    now = datetime.now(timezone.utc)

    expire = now + expires_delta

    payload = {
        "sub": subject,

        "type": token_type.value,

        "iat": now,

        "exp": expire,

        "jti": str(uuid.uuid4()),

        "iss": JWT_ISSUER
    }

    if extra:
        payload.update(extra)

    return jwt.encode(
        payload,
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM
    )


# =============================================================================
# CREATE ACCESS TOKEN
# =============================================================================

def create_access_token(
    subject: str,
    extra: dict[str, Any] | None = None
) -> str:
    """
    Generate short-lived access token.
    """

    return _create_token(
        subject=subject,

        token_type=TokenType.access,

        expires_delta=timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        ),

        extra=extra
    )


# =============================================================================
# CREATE REFRESH TOKEN
# =============================================================================

def create_refresh_token(subject: str) -> str:
    """
    Generate long-lived refresh token.
    """

    return _create_token(
        subject=subject,

        token_type=TokenType.refresh,

        expires_delta=timedelta(
            days=REFRESH_TOKEN_EXPIRE_DAYS
        )
    )


# =============================================================================
# TOKEN DECODING
# =============================================================================

def decode_token(
    token: str,
    expected_type: TokenType
) -> dict[str, Any]:
    """
    Decode and validate JWT token.

    Security checks:

        • Signature verification
        • Expiration verification
        • Token type validation
        • Subject validation
        • Issuer validation
        • Payload integrity validation

    Parameters
    ----------
    token : str

    expected_type : TokenType

    Returns
    -------
    dict
        Valid decoded payload.

    Raises
    ------
    ValueError
        If token is invalid.
    """

    try:
        payload = jwt.decode(
            token,

            JWT_SECRET_KEY,

            algorithms=[JWT_ALGORITHM]
        )

    except JWTError as exc:

        logger.warning(
            "Invalid JWT token detected"
        )

        raise ValueError(
            "Invalid or expired token"
        ) from exc

    # Verify issuer

    if payload.get("iss") != JWT_ISSUER:

        logger.warning(
            "JWT issuer validation failed"
        )

        raise ValueError(
            "Invalid token issuer"
        )

    # Verify token type

    if payload.get("type") != expected_type.value:

        logger.warning(
            "JWT token type mismatch"
        )

        raise ValueError(
            "Invalid token type"
        )

    # Verify subject

    if not payload.get("sub"):

        logger.warning(
            "JWT subject missing"
        )

        raise ValueError(
            "Invalid token payload"
        )

    # Verify jti

    if not payload.get("jti"):

        logger.warning(
            "JWT missing unique token identifier"
        )

        raise ValueError(
            "Invalid token payload"
        )

    return payload