"""
services/auth/dependencies.py
================================================================================
CyberSafe Connect Authentication Microservice
================================================================================

FastAPI dependency providers and shared authentication helpers.

This module centralizes reusable dependencies required by API routes.

Unlike services.py, this file contains NO business logic.

It provides infrastructure-level helpers used across the authentication service.

--------------------------------------------------------------------------------
RESPONSIBILITIES
--------------------------------------------------------------------------------

This module is responsible for:

    • Database session lifecycle management
    • OTP generation utilities
    • User serialization helpers
    • JWT authentication dependency
    • Current authenticated user extraction
    • Protected route authorization workflow

This layer exists to prevent duplicated authentication logic across routes.

--------------------------------------------------------------------------------
SECURITY PRINCIPLES
--------------------------------------------------------------------------------

• Database sessions must always be properly closed
• OTP codes must be unpredictable
• OTP expiration must use UTC timestamps
• Protected routes require valid JWT access token
• Suspended/deleted accounts must never access protected resources
• Authentication failures must return controlled error responses

--------------------------------------------------------------------------------
ARCHITECTURE RULES
--------------------------------------------------------------------------------

This file MUST NOT contain:

    • Business logic
    • Database model definitions
    • API route definitions

Business logic belongs to:

    • services.py

Route definitions belong to:

    • routes.py

Security cryptographic logic belongs to:

    • security.py

================================================================================
"""

# =============================================================================
# STANDARD LIBRARY IMPORTS
# =============================================================================

import random
from datetime import datetime, timedelta, timezone


# =============================================================================
# FASTAPI IMPORTS
# =============================================================================

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


# =============================================================================
# SQLALCHEMY IMPORTS
# =============================================================================

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


# =============================================================================
# INTERNAL IMPORTS
# =============================================================================

from config import OTP_EXPIRE_MINUTES
from database import AsyncSessionLocal
from enums import AccountStatus, TokenType
from models import User
from security import decode_token


# =============================================================================
# SECURITY CONFIGURATION
# =============================================================================

# HTTP Bearer authentication scheme used for protected endpoints.
# auto_error=False allows custom error handling.
bearer_scheme = HTTPBearer(auto_error=False)


# =============================================================================
# DATABASE SESSION DEPENDENCY
# =============================================================================

async def get_async_db():
    """
    Provide SQLAlchemy database session.

    This dependency creates a request-scoped database session
    and guarantees cleanup after request completion.

    Security considerations:

        • Prevent connection leakage
        • Ensure session closure even on exception
        • Avoid stale connections

    Yields
    ------
    Session
        Active SQLAlchemy session.
    """

    async with AsyncSessionLocal() as db:
        yield db

# =============================================================================
# OTP GENERATION
# =============================================================================

def generate_otp() -> tuple[str, datetime]:
    """
    Generate secure one-time verification code.

    Produces:

        • Random 6-digit verification code
        • UTC expiration timestamp

    Security considerations:

        • Randomized code generation
        • Fixed expiration window
        • UTC consistency across distributed services

    Returns
    -------
    tuple[str, datetime]

        code:
            Six-digit OTP.

        expires_at:
            UTC expiration timestamp.
    """

    code = f"{random.randint(0, 999999):06d}"

    expires_at = datetime.now(
        timezone.utc
    ) + timedelta(
        minutes=OTP_EXPIRE_MINUTES
    )

    return code, expires_at


# =============================================================================
# USER SERIALIZATION
# =============================================================================

def user_to_dict(user: User) -> dict:
    """
    Serialize User ORM object into safe API response.

    Security rules:

        • Never expose password hash
        • Never expose OTP verification code
        • Never expose internal security metadata

    Parameters
    ----------
    user : User
        SQLAlchemy User instance.

    Returns
    -------
    dict
        Sanitized user payload safe for API responses.
    """

    return {
        "id": user.id,

        "fullname": user.fullname,

        "email": user.email,

        "role": user.role.value,

        "is_verified": user.is_verified,

        "account_status": user.account_status.value,
    }


# =============================================================================
# CURRENT AUTHENTICATED USER DEPENDENCY
# =============================================================================

async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(
        bearer_scheme
    ),
    db: AsyncSession = Depends(
        get_async_db
    ),
) -> User:
    """
    Retrieve currently authenticated user.

    Authentication workflow:

        1. Extract Bearer token
        2. Decode JWT access token
        3. Validate token signature
        4. Validate token expiration
        5. Extract user identifier
        6. Load user from database
        7. Verify account status
        8. Return authenticated user

    Security checks:

        • Missing token rejection
        • Invalid JWT rejection
        • Expired token rejection
        • User existence verification
        • Suspended account blocking
        • Deleted account blocking

    Parameters
    ----------
    credentials :
        HTTP Bearer token extracted by FastAPI.

    db :
        Active SQLAlchemy database session.

    Returns
    -------
    User
        Authenticated user object.

    Raises
    ------
    HTTPException

        401:

            • Missing token
            • Invalid token
            • Expired token
            • Unknown user

        403:

            • Suspended account
            • Deleted account
    """

    # -------------------------------------------------------------------------
    # Missing authentication token
    # -------------------------------------------------------------------------

    if credentials is None:

        raise HTTPException(
            status_code=401,

            detail="Authentication required",

            headers={
                "X-Error-Code": "AUTH_REQUIRED"
            },
        )

    # -------------------------------------------------------------------------
    # JWT validation
    # -------------------------------------------------------------------------

    try:

        payload = decode_token(
            credentials.credentials,
            TokenType.access
        )

    except ValueError:

        raise HTTPException(
            status_code=401,

            detail="Invalid or expired access token",

            headers={
                "X-Error-Code": "INVALID_TOKEN"
            },
        )

    # -------------------------------------------------------------------------
    # User existence validation
    # -------------------------------------------------------------------------
    
    result = await db.execute(
        select(User).where(User.id == int(payload["sub"]))
    )

    user = result.scalar_one_or_none()

    if not user:

        raise HTTPException(
            status_code=401,

            detail="User not found",

            headers={
                "X-Error-Code": "USER_NOT_FOUND"
            },
        )

    # -------------------------------------------------------------------------
    # Account status validation
    # -------------------------------------------------------------------------

    if user.account_status in (
        AccountStatus.suspended,
        AccountStatus.deleted
    ):

        raise HTTPException(
            status_code=403,

            detail="Account is not active",

            headers={
                "X-Error-Code": "ACCOUNT_BLOCKED"
            },
        )

    # -------------------------------------------------------------------------
    # Authentication successful
    # -------------------------------------------------------------------------

    return user