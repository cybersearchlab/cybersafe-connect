"""
services/academy/dependencies.py
================================================================================
CyberSafe Connect Academy Microservice
================================================================================

FastAPI dependency providers for request lifecycle management.

This module centralizes reusable dependencies used by academy endpoints.

Responsibilities
--------------------------------------------------------------------------------

Authentication Layer

    • Extract JWT token from Authorization header
    • Validate authenticated users
    • Support optional authentication
    • Build authenticated user context

Database Layer

    • Create SQLAlchemy session per request
    • Guarantee proper session cleanup

Authorization Layer

    • Enforce administrator-only endpoints
    • Restrict unauthorized access

Role Resolution

    • Determine accessible academy content
    • Filter modules according to authenticated role

Security Principles
--------------------------------------------------------------------------------

• Never trust client-supplied JWT blindly
• Validate JWT before extracting claims
• Never trust arbitrary roles from token payload
• Prevent privilege escalation attacks
• Reject malformed authentication payloads
• Protect administrative endpoints

Architecture
--------------------------------------------------------------------------------

Academy does NOT communicate with Auth database.

Authentication flow:

    Client
        ↓
    Auth Service issues JWT
        ↓
    Academy validates JWT locally
        ↓
    Academy trusts validated claims

No shared database is allowed between microservices.

Business logic belongs to:

    • services.py

JWT cryptographic validation belongs to:

    • security.py

================================================================================
"""

import logging
from dataclasses import dataclass
from typing import Generator

from fastapi import Depends, HTTPException
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer
)
from sqlalchemy.orm import Session

from database import SessionLocal
from security import (
    decode_access_token,
    extract_user_id
)

logger = logging.getLogger(__name__)


# =============================================================================
# SECURITY SCHEME
# =============================================================================
#
# HTTP Bearer authentication scheme.
#
# auto_error=False allows manual authentication handling
# for optional authentication endpoints.
#
# Example:
#
#       Authorization: Bearer eyJhb...
#
# =============================================================================

bearer_scheme = HTTPBearer(
    auto_error=False
)


# =============================================================================
# AUTHENTICATED USER MODEL
# =============================================================================
#
# Internal representation of authenticated user extracted
# from validated JWT token.
#
# This avoids querying Auth database.
#
# Fields:
#
#       id      → internal user identifier
#       email   → authenticated email address
#       role    → citizen / company / admin
#
# =============================================================================

@dataclass
class AuthUser:
    """
    Represents authenticated user context.

    Built from validated JWT claims.
    """

    id: int

    email: str | None

    role: str


# =============================================================================
# DATABASE SESSION DEPENDENCY
# =============================================================================
#
# Creates SQLAlchemy session for current request lifecycle.
#
# Security:
#
# Always closes database connection after request completion
# to prevent connection leaks.
#
# FastAPI automatically injects this dependency.
#
# =============================================================================

def get_db() -> Generator[Session, None, None]:
    """
    Create request-scoped database session.

    Yields
    ------
    Session
        Active SQLAlchemy session.
    """

    db = SessionLocal()

    try:

        yield db

    finally:

        db.close()


# =============================================================================
# INTERNAL JWT USER EXTRACTION
# =============================================================================
#
# Converts validated JWT payload into internal AuthUser object.
#
# Security checks:
#
#     • Validate subject field
#     • Validate role integrity
#     • Prevent forged role injection
#
# Example forged payload:
#
#     {
#         "role": "superadmin"
#     }
#
# Must be rejected.
#
# =============================================================================

def _user_from_payload(
    payload: dict,
) -> AuthUser:
    """
    Convert decoded JWT payload into AuthUser.

    Security validation includes role integrity checks.

    Parameters
    ----------
    payload : dict
        Decoded validated JWT payload.

    Returns
    -------
    AuthUser

    Raises
    ------
    ValueError
        If payload structure is invalid.
    """

    allowed_roles = {
        "citizen",
        "company",
        "admin"
    }

    try:

        user_id = extract_user_id(
            payload
        )

        role = payload.get(
            "role"
        )

        # ---------------------------------------------------------------------
        # Role integrity validation
        # ---------------------------------------------------------------------

        if role not in allowed_roles:

            logger.warning(
                "Invalid role detected in JWT payload"
            )

            raise ValueError(
                "Invalid user role"
            )

        return AuthUser(
            id=user_id,

            email=payload.get(
                "email"
            ),

            role=role
        )

    except ValueError as exc:

        logger.warning(
            "Malformed JWT payload detected"
        )

        raise ValueError(
            "Invalid token payload"
        ) from exc


# =============================================================================
# OPTIONAL AUTHENTICATION DEPENDENCY
# =============================================================================
#
# Attempts user authentication.
#
# Behavior:
#
#     • Missing token → anonymous access
#     • Invalid token → anonymous access
#     • Valid token → authenticated user
#
# Used for partially public endpoints.
#
# Example:
#
#     Public academy modules
#
# =============================================================================

def get_optional_user(
    credentials:
    HTTPAuthorizationCredentials | None = Depends(
        bearer_scheme
    ),
) -> AuthUser | None:
    """
    Attempt user authentication.

    Returns
    -------
    AuthUser | None
    """

    # -------------------------------------------------------------------------
    # Anonymous request
    # -------------------------------------------------------------------------

    if credentials is None:

        logger.debug(
            "Anonymous access request"
        )

        return None

    try:

        payload = decode_access_token(
            credentials.credentials
        )

        return _user_from_payload(
            payload
        )

    except ValueError:

        logger.warning(
            "Optional authentication failed"
        )

        return None


# =============================================================================
# REQUIRED AUTHENTICATION DEPENDENCY
# =============================================================================
#
# Forces JWT authentication.
#
# Security:
#
# Endpoint access denied if:
#
#     • Missing token
#     • Invalid signature
#     • Expired token
#     • Invalid issuer
#     • Invalid audience
#     • Invalid role
#
# Used for protected academy resources.
#
# =============================================================================

def get_current_user(
    credentials:
    HTTPAuthorizationCredentials | None = Depends(
        bearer_scheme
    ),
) -> AuthUser:
    """
    Authenticate current user.

    Returns
    -------
    AuthUser

    Raises
    ------
    HTTPException
        If authentication fails.
    """

    if credentials is None:

        raise HTTPException(
            status_code=401,

            detail="Authentication required",

            headers={
                "X-Error-Code":
                    "AUTH_REQUIRED"
            },
        )

    try:

        payload = decode_access_token(
            credentials.credentials
        )

        return _user_from_payload(
            payload
        )

    except ValueError:

        logger.warning(
            "Invalid authentication token"
        )

        raise HTTPException(
            status_code=401,

            detail="Invalid or expired access token",

            headers={
                "X-Error-Code":
                    "INVALID_TOKEN"
            },
        )


# =============================================================================
# ADMINISTRATOR ACCESS CONTROL
# =============================================================================
#
# Restricts endpoint access to administrator accounts only.
#
# Security:
#
# Blocks privilege escalation attempts from:
#
#     • citizen users
#     • company users
#
# Example:
#
#     POST /academy/admin/create-course
#
# =============================================================================

def require_admin(
    user: AuthUser = Depends(
        get_current_user
    ),
) -> AuthUser:
    """
    Restrict endpoint to administrators only.

    Parameters
    ----------
    user : AuthUser

    Returns
    -------
    AuthUser

    Raises
    ------
    HTTPException
        If user is not administrator.
    """

    if user.role != "admin":

        logger.warning(
            "Unauthorized admin access attempt "
            f"user={user.id}"
        )

        raise HTTPException(
            status_code=403,

            detail="Admin access required",

            headers={
                "X-Error-Code":
                    "FORBIDDEN"
            },
        )

    return user


# =============================================================================
# ROLE FILTERING HELPER
# =============================================================================
#
# Determines academy content accessible to current user.
#
# Rules:
#
#     Anonymous
#         → citizen + both
#
#     Citizen
#         → citizen + both
#
#     Company
#         → company + both
#
#     Admin
#         → unrestricted access
#
# Used for filtering educational modules.
#
# =============================================================================

def target_roles_for_user(
    user: AuthUser | None,
) -> list[str]:
    """
    Determine accessible academy content.

    Parameters
    ----------
    user : AuthUser | None

    Returns
    -------
    list[str]
        Allowed content roles.
    """

    # Anonymous visitor

    if user is None:

        return [
            "citizen",
            "both",
        ]

    # Company account

    if user.role == "company":

        return [
            "company",
            "both",
        ]

    # Administrator

    if user.role == "admin":

        return [
            "citizen",
            "company",
            "both",
        ]

    # Default citizen

    return [
        "citizen",
        "both",
    ]