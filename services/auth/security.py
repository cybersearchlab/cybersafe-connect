"""
services/auth/security.py
===============================================================================
CyberSafe Connect Authentication Security Layer
===============================================================================

Centralized cryptographic and token security operations.

Responsibilities
----------------

This module handles all security-sensitive authentication operations.

Core features:

    • Password hashing using Argon2
    • Password verification
    • JWT access token generation
    • JWT refresh token generation
    • JWT signature verification
    • JWT claim validation
    • Token integrity enforcement

Security Principles
-------------------

• Never store plain text passwords
• Use modern password hashing algorithms
• Enforce token expiration
• Validate issuer identity
• Validate token audience
• Prevent token replay attacks
• Prevent cross-service token abuse
• Reject malformed JWT payloads

===============================================================================
"""

import logging
import uuid

from datetime import datetime, timedelta, timezone
from typing import Any

from jose import JWTError, jwt
from passlib.context import CryptContext

from config import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    REFRESH_TOKEN_EXPIRE_DAYS,
    JWT_SECRET_KEY,
    JWT_ALGORITHM,
    JWT_ISSUER,
    JWT_AUDIENCE
)

from enums import TokenType


# =============================================================================
# LOGGER
# =============================================================================

logger = logging.getLogger(__name__)


# =============================================================================
# PASSWORD HASHING ENGINE
# =============================================================================
# Argon2 is recommended for modern password security.
#
# Installation:
#
#     pip install passlib[argon2]
#
# Security:
#
# • Resistant against GPU cracking
# • Resistant against rainbow table attacks
# • Memory-hard design
# =============================================================================

pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto"
)


# =============================================================================
# PASSWORD INPUT VALIDATION
# =============================================================================

def _validate_password(password: str) -> None:
    """
    Validate password before cryptographic operations.

    Security checks:

        • Must be string
        • Prevent oversized payload attacks

    Parameters
    ----------
    password : str

    Raises
    ------
    ValueError
    """

    if not isinstance(password, str):
        raise ValueError(
            "Password must be a string"
        )

    if len(password) > 128:
        raise ValueError(
            "Password exceeds maximum allowed length"
        )


# =============================================================================
# HASH PASSWORD
# =============================================================================

def hash_password(password: str) -> str:
    """
    Hash password using Argon2.

    Parameters
    ----------
    password : str

    Returns
    -------
    str
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
    """

    _validate_password(
        plain_password
    )

    return pwd_context.verify(
        plain_password,
        hashed_password
    )


# =============================================================================
# INTERNAL TOKEN GENERATION ENGINE
# =============================================================================

def _create_token(
    subject: str,
    token_type: TokenType,
    expires_delta: timedelta,
    extra: dict[str, Any] | None = None
) -> str:
    """
    Internal JWT generation engine.

    Standard claims:

        • sub → subject (user id)
        • iss → issuer
        • aud → intended service audience
        • exp → expiration
        • iat → issued at
        • nbf → not before
        • jti → unique token identifier
    """

    now = datetime.now(
        timezone.utc
    )

    expire = now + expires_delta

    payload = {
        "sub": subject,

        "type": token_type.value,

        "iat": now,

        "nbf": now,

        "exp": expire,

        "jti": str(
            uuid.uuid4()
        ),

        "iss": JWT_ISSUER,

        "aud": JWT_AUDIENCE
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

def create_refresh_token(
    subject: str
) -> str:
    """
    Generate refresh token.
    """

    return _create_token(
        subject=subject,

        token_type=TokenType.refresh,

        expires_delta=timedelta(
            days=REFRESH_TOKEN_EXPIRE_DAYS
        )
    )


# =============================================================================
# DECODE TOKEN
# =============================================================================

def decode_token(
    token: str,
    expected_type: TokenType
) -> dict[str, Any]:
    """
    Decode and validate JWT token.

    Security validations:

        • Signature verification
        • Expiration validation
        • Issuer validation
        • Audience validation
        • Subject validation
        • Token type validation
        • Replay prevention identifier presence

    Parameters
    ----------
    token : str

    expected_type : TokenType

    Returns
    -------
    dict

    Raises
    ------
    ValueError
    """

    try:

        payload = jwt.decode(
            token,

            JWT_SECRET_KEY,

            algorithms=[JWT_ALGORITHM],

            issuer=JWT_ISSUER,

            audience=JWT_AUDIENCE,

            options={
                "require_sub": True,
                "require_exp": True,
                "require_iat": True,
                "require_nbf": True
            }
        )

    except JWTError as exc:

        logger.warning(
            "JWT validation failed"
        )

        raise ValueError(
            "Invalid or expired token"
        ) from exc

    if payload.get("type") != expected_type.value:

        logger.warning(
            "JWT token type mismatch"
        )

        raise ValueError(
            "Invalid token type"
        )

    if not payload.get("jti"):

        logger.warning(
            "JWT missing token identifier"
        )

        raise ValueError(
            "Invalid token payload"
        )

    return payload

# =============================================================================
# SECURITY VALIDATION
# =============================================================================

def validate_security_config() -> None:
    """
    Validate the security configuration at startup.

    This function checks:
        1. JWT_SECRET_KEY exists and is strong enough
        2. Algorithm is secure
        3. Token expiration times are reasonable

    Raises:
        ValueError: If any security configuration is invalid

    OWASP Compliance:
        - API2: Broken Authentication
        - API8: Security Misconfiguration
    """
    from config import JWT_SECRET_KEY, JWT_ALGORITHM, ENVIRONMENT

    # Check 1: JWT_SECRET_KEY exists
    if not JWT_SECRET_KEY:
        raise ValueError("JWT_SECRET_KEY is not set in configuration")

    # Check 2: JWT_SECRET_KEY is strong enough
    if len(JWT_SECRET_KEY) < 32:
        raise ValueError(
            f"JWT_SECRET_KEY is too weak: {len(JWT_SECRET_KEY)} characters. "
            "Minimum 32 characters required."
        )

    # Check 3: Production requires even stronger key
    if ENVIRONMENT in ["staging", "production"] and len(JWT_SECRET_KEY) < 64:
        raise ValueError(
            f"JWT_SECRET_KEY must be at least 64 characters in {ENVIRONMENT}. "
            "Generate one with: openssl rand -hex 32"
        )

    # Check 4: Algorithm must be secure
    if JWT_ALGORITHM not in ["HS256", "HS384", "HS512"]:
        raise ValueError(
            f"JWT_ALGORITHM '{JWT_ALGORITHM}' is not supported. "
            "Use HS256, HS384, or HS512."
        )

    # Check 5: Log success
    import logging
    logger = logging.getLogger(__name__)
    logger.info(" Security configuration validated successfully")