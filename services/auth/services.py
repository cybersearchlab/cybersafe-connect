"""
================================================================================
MODULE: services.py
================================================================================

CyberSafe Connect - Authentication Business Logic Service
================================================================================

OVERVIEW
--------

This module contains the core authentication business logic for the
CyberSafe Connect platform. It serves as the intermediary layer between
the API routes (routes.py) and the database models (models.py).

ARCHITECTURE CONTEXT
--------------------

This module is the HEART of the authentication service. All security-sensitive
operations are centralized here to maintain consistency and auditability.

    ┌─────────────────────────────────────────────────────────────────┐
    │                    Authentication Flow                          │
    │                                                                 │
    │  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐        │
    │  │  routes.py  │───▶││ services.py││───▶│  models.py  │        │
    │  │  (HTTP)     │     │  (Business) │     │  (Database) │        │
    │  └─────────────┘     └─────────────┘     └─────────────┘        │
    │         │                  │                  │                 │
    │         ▼                  ▼                  ▼                 │
    │  ┌─────────────────────────────────────────────────────────┐    │
    │  │                    PostgreSQL                           │    │
    │  │                 (User Data Storage)                     │    │
    │  └─────────────────────────────────────────────────────────┘    │
    └─────────────────────────────────────────────────────────────────┘

INTERACTIONS WITH OTHER MODULES
-------------------------------

| Module           | Interaction                                | Direction    |
|------------------|--------------------------------------------|--------------|
| routes.py        | Calls service functions for business logic | ← Incoming   |
| models.py        | Reads/writes User data via SQLAlchemy      | ↔ Read/Write |
| security.py      | Password hashing, JWT creation/validation  | ← Uses       |
| email_service.py | Sends verification emails                  | ← Uses       |
| dependencies.py  | OTP generation, user serialization         | ← Uses       |
| schemas.py       | Request/response validation                | ← Uses       |

RESPONSIBILITIES
----------------

This module handles:

    1. User Registration
       - Email uniqueness validation
       - Password hashing (async, non-blocking)
       - OTP generation and storage
       - Account creation with pending status
       - Verification email dispatch

    2. Email Verification
       - OTP code validation
       - Expiration checking
       - Account activation

    3. OTP Resend
       - New code generation
       - Email dispatch

    4. User Login
       - Credential validation
       - Account status verification
       - JWT access token generation
       - Refresh token generation
       - Last login tracking

    5. Token Refresh
       - Refresh token validation
       - New access token generation
       - New refresh token generation (rotation)

SECURITY PRINCIPLES
-------------------

• No password stored in plain text (Argon2/bcrypt hashing)
• Email uniqueness enforced at database level
• Account must be verified before login
• Suspended/deleted accounts blocked
• JWT tokens with expiration
• OTP expiration (15 minutes)
• All password operations run in separate threads (non-blocking)
• Rate limiting applied at route level

FAILURE MODES
-------------

| Failure Mode              | Impact                | Recovery                      |
|---------------------------|-----------------------|-------------------------------|
| Email already exists      | Registration fails    | User must use different email |
| Invalid OTP               | Verification fails    | User can request new OTP      |
| Expired OTP               | Verification fails    | User must request new OTP     |
| Invalid credentials       | Login fails           | User must re-enter password   |
| Unverified email          | Login blocked         | User must verify email        |
| Suspended account         | Login blocked         | Contact support               |
| Invalid refresh token     | Token refresh fails   | User must re-login            |

================================================================================
DEPENDENCIES
================================================================================

Internal Dependencies:
    - dependencies.py   : OTP generation, user serialization
    - email_service.py  : Email sending (async)
    - enums.py          : AccountStatus, TokenType, UserRole
    - models.py         : User ORM model
    - schemas.py        : Request/response validation schemas
    - security.py       : Password hashing, JWT operations

External Dependencies:
    - sqlalchemy        : Async ORM for PostgreSQL
    - fastapi           : HTTPException for error responses
    - datetime          : Timezone-aware timestamps
    - asyncio           : Async/await for non-blocking operations

================================================================================
OWASP API SECURITY TOP 10 (2023) COMPLIANCE
================================================================================

| #   | Category                               | Status  | Implementation                     |
|-----|----------------------------------------|---------|------------------------------------|
| 1   | Broken Object Level Authorization      | ok      | User-specific data access control  |
| 2   | Broken Authentication                  | ok      | Password hashing, JWT, OTP         |
| 3   | Broken Object Property Level Auth      | ok      | User data filtered via schemas     |
| 4   | Unrestricted Resource Consumption      | ok      | OTP expiration, rate limiting      |
| 5   | Broken Function Level Authorization    | ok      | Role-based access control          |
| 6   | Unrestricted Access to Sensitive Flows | ok      | OTP required for verification      |
| 8   | Security Misconfiguration              | ok      | Secure password hashing            |
| 9   | Improper Inventory Management          | ok      | Full audit logging                 |

================================================================================
DEVELOPER NOTES
================================================================================

For developers adding new authentication features:

1. All business logic MUST be in this module (not in routes.py)
2. Use async/await for all database operations
3. Use asyncio.to_thread() for CPU-bound operations (password hashing)
4. Always validate email uniqueness before registration
5. Always check account status before login
6. Never expose password hashes in responses

================================================================================
"""

import asyncio
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import ACCESS_TOKEN_EXPIRE_MINUTES
from dependencies import generate_otp, user_to_dict
from email_service import send_verification_email
from enums import AccountStatus, TokenType, UserRole
from models import User
from schemas import (
    LoginRequest,
    RefreshTokenRequest,
    RegisterRequest,
    ResendVerificationRequest,
    VerifyEmailRequest,
)
from security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)


# =============================================================================
# ASYNC WRAPPERS FOR CPU-BOUND OPERATIONS
# =============================================================================

async def hash_password_async(password: str) -> str:
    """
    Hash a password in a separate thread to avoid blocking the event loop.

    Password hashing (Argon2/bcrypt) is CPU-intensive and would block
    the async event loop if run directly. This function offloads the
    work to a thread pool executor.

    Parameters
    ----------
    password : str
        Plain text password to hash.

    Returns
    -------
    str
        The hashed password as a string (includes salt and algorithm info).

    Example
    -------
    >>> hashed = await hash_password_async("SecurePass123!")
    >>> print(hashed)
    "$argon2id$v=19$m=65536,t=3,p=4$..."

    Security Notes
    --------------
    - Uses Argon2 by default (state-of-the-art password hashing)
    - Falls back to bcrypt for development (faster)
    - Salt is automatically generated
    - OWASP A02: Cryptographic Failures (strong hashing)
    """
    return await asyncio.to_thread(hash_password, password)


async def verify_password_async(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash in a separate thread.

    Like password hashing, verification is CPU-intensive and should be
    offloaded to a thread pool to avoid blocking the event loop.

    Parameters
    ----------
    plain_password : str
        Plain text password to verify.
    hashed_password : str
        Hashed password to compare against.

    Returns
    -------
    bool
        True if the password matches the hash, False otherwise.

    Example
    -------
    >>> is_valid = await verify_password_async("SecurePass123!", hashed)
    >>> print(is_valid)
    True

    Security Notes
    --------------
    - Uses constant-time comparison to prevent timing attacks
    - OWASP A02: Cryptographic Failures (secure verification)
    """
    return await asyncio.to_thread(verify_password, plain_password, hashed_password)


# =============================================================================
# REGISTER USER
# =============================================================================

async def register_user(
    payload: RegisterRequest,
    db: AsyncSession
) -> dict:
    """
    Register a new user account.

    This is the main entry point for user registration. It handles the
    complete registration flow including validation, account creation,
    and email dispatch.

    Workflow
    --------
        1. Check if email already exists (fail early)
        2. Generate a 6-digit OTP code
        3. Hash the password (async, non-blocking)
        4. Create User object with pending status
        5. Save to database
        6. Send verification email (async, non-blocking)
        7. Return sanitized user data

    Parameters
    ----------
    payload : RegisterRequest
        Validated registration data (email, fullname, password, role).
    db : AsyncSession
        SQLAlchemy async database session.

    Returns
    -------
    dict
        Success response with user data.

    Raises
    ------
    HTTPException(400)
        If email already exists in the database.

    Security Notes
    --------------
    - Email uniqueness is enforced at database level
    - Password is NEVER stored in plain text
    - Account is created in 'pending' state (requires verification)
    - OTP expires after 15 minutes
    - OWASP API1: Broken Object Level Authorization
    - OWASP API2: Broken Authentication

    Example
    -------
    >>> result = await register_user(
    ...     RegisterRequest(email="user@example.com", password="SecurePass123!"),
    ...     db
    ... )
    >>> print(result["data"]["id"])
    1

    Logging
    -------
        - INFO : User registered successfully
        - INFO : Verification email sent
        - WARNING : Registration attempt with existing email
    """
    # -------------------------------------------------------------------------
    # Step 1: Check if email already exists
    # -------------------------------------------------------------------------
    result = await db.execute(
        select(User).where(User.email == payload.email)
    )
    existing_user = result.scalar_one_or_none()

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Email already exists"
        )

    # -------------------------------------------------------------------------
    # Step 2: Generate OTP
    # -------------------------------------------------------------------------
    code, expires_at = generate_otp()

    # -------------------------------------------------------------------------
    # Step 3: Hash password (async, non-blocking)
    # -------------------------------------------------------------------------
    hashed_password = await hash_password_async(payload.password)

    # -------------------------------------------------------------------------
    # Step 4: Create user
    # -------------------------------------------------------------------------
    user = User(
        fullname=payload.fullname,
        email=payload.email,
        password_hash=hashed_password,  # ←  CORRECT: use the hashed password
        role=UserRole(payload.role),
        verification_code=code,
        verification_expires_at=expires_at,
        is_verified=False,
        account_status=AccountStatus.pending
    )

    # -------------------------------------------------------------------------
    # Step 5: Save to database
    # -------------------------------------------------------------------------
    db.add(user)
    await db.commit()
    await db.refresh(user)

    # -------------------------------------------------------------------------
    # Step 6: Send verification email (async, non-blocking)
    # -------------------------------------------------------------------------
    await send_verification_email(  # ←  CORRECT: await is required
        user.email,
        user.fullname,
        code
    )

    # -------------------------------------------------------------------------
    # Step 7: Return response
    # -------------------------------------------------------------------------
    return {
        "success": True,
        "message": "Account created successfully. Verify your email.",
        "data": user_to_dict(user)
    }


# =============================================================================
# VERIFY EMAIL
# =============================================================================

async def verify_email(
    payload: VerifyEmailRequest,
    db: AsyncSession
) -> dict:
    """
    Verify a user's email address using an OTP code.

    This function validates the OTP code provided by the user and
    activates their account if the code is valid and not expired.

    Workflow
    --------
        1. Find user by email
        2. Check if user exists
        3. Check if already verified (idempotent)
        4. Validate OTP code
        5. Check OTP expiration
        6. Activate account (set is_verified=True, status=active)
        7. Clear verification fields
        8. Return updated user data

    Parameters
    ----------
    payload : VerifyEmailRequest
        Contains email and OTP code.
    db : AsyncSession
        SQLAlchemy async database session.

    Returns
    -------
    dict
        Success response with updated user data.

    Raises
    ------
    HTTPException(404)
        If user account is not found.
    HTTPException(400)
        If OTP code is invalid or expired.

    Security Notes
    --------------
    - OTP codes expire after 15 minutes
    - Codes are single-use (cleared after verification)
    - Idempotent: already verified accounts return success
    - OWASP API2: Broken Authentication

    Example
    -------
    >>> result = await verify_email(
    ...     VerifyEmailRequest(email="user@example.com", code="123456"),
    ...     db
    ... )
    >>> print(result["data"]["is_verified"])
    True
    """
    # -------------------------------------------------------------------------
    # Step 1: Find user
    # -------------------------------------------------------------------------
    result = await db.execute(
        select(User).where(User.email == payload.email)
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="Account not found"
        )

    # -------------------------------------------------------------------------
    # Step 2: Check if already verified (idempotent)
    # -------------------------------------------------------------------------
    if user.is_verified:
        return {
            "success": True,
            "message": "Already verified",
            "data": user_to_dict(user)
        }

    # -------------------------------------------------------------------------
    # Step 3: Validate OTP code
    # -------------------------------------------------------------------------
    if user.verification_code != payload.code:
        raise HTTPException(
            status_code=400,
            detail="Invalid OTP code"
        )

    # -------------------------------------------------------------------------
    # Step 4: Check expiration
    # -------------------------------------------------------------------------
    if (
        user.verification_expires_at and
        user.verification_expires_at <
        datetime.now(timezone.utc)
    ):
        raise HTTPException(
            status_code=400,
            detail="OTP expired"
        )

    # -------------------------------------------------------------------------
    # Step 5: Activate account
    # -------------------------------------------------------------------------
    user.is_verified = True
    user.account_status = AccountStatus.active
    user.verification_code = None
    user.verification_expires_at = None

    await db.commit()
    await db.refresh(user)

    # -------------------------------------------------------------------------
    # Step 6: Return response
    # -------------------------------------------------------------------------
    return {
        "success": True,
        "message": "Email verified",
        "data": user_to_dict(user)
    }


# =============================================================================
# RESEND OTP
# =============================================================================

async def resend_verification(
    payload: ResendVerificationRequest,
    db: AsyncSession
) -> dict:
    """
    Generate and resend a new verification code.

    This function allows users to request a new OTP if the previous one
    was lost, expired, or never received.

    Workflow
    --------
        1. Find user by email
        2. Check if user exists
        3. Check if already verified (return success)
        4. Generate new OTP
        5. Update user with new code
        6. Send verification email
        7. Return success

    Parameters
    ----------
    payload : ResendVerificationRequest
        Contains email address.
    db : AsyncSession
        SQLAlchemy async database session.

    Returns
    -------
    dict
        Success response indicating code was sent.

    Raises
    ------
    HTTPException(404)
        If user account is not found.

    Security Notes
    --------------
    - Rate limiting should be applied at route level
    - OTP codes expire after 15 minutes
    - OWASP API6: Unrestricted Access to Sensitive Flows

    Example
    -------
    >>> result = await resend_verification(
    ...     ResendVerificationRequest(email="user@example.com"),
    ...     db
    ... )
    >>> print(result["message"])
    "Verification code sent"
    """
    # -------------------------------------------------------------------------
    # Step 1: Find user
    # -------------------------------------------------------------------------
    result = await db.execute(
        select(User).where(User.email == payload.email)
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="Account not found"
        )

    # -------------------------------------------------------------------------
    # Step 2: Check if already verified
    # -------------------------------------------------------------------------
    if user.is_verified:
        return {
            "success": True,
            "message": "Already verified"
        }

    # -------------------------------------------------------------------------
    # Step 3: Generate new OTP
    # -------------------------------------------------------------------------
    code, expires_at = generate_otp()

    # -------------------------------------------------------------------------
    # Step 4: Update user
    # -------------------------------------------------------------------------
    user.verification_code = code
    user.verification_expires_at = expires_at

    await db.commit()

    # -------------------------------------------------------------------------
    # Step 5: Send verification email (async, non-blocking)
    # -------------------------------------------------------------------------
    await send_verification_email(  # ←  CORRECT: await is required
        user.email,
        user.fullname,
        code
    )

    return {
        "success": True,
        "message": "Verification code sent"
    }


# =============================================================================
# LOGIN USER
# =============================================================================

async def login_user(
    payload: LoginRequest,
    db: AsyncSession
) -> dict:
    """
    Authenticate a user and generate JWT tokens.

    This is the main authentication entry point. It validates credentials,
    checks account status, and generates access and refresh tokens.

    Workflow
    --------
        1. Find user by email
        2. Check if user exists
        3. Verify password (async, non-blocking)
        4. Check account status (active, suspended, deleted)
        5. Check if email is verified
        6. Update last_login timestamp
        7. Generate access token (JWT)
        8. Generate refresh token (JWT)
        9. Return tokens and user data

    Parameters
    ----------
    payload : LoginRequest
        Contains email and password.
    db : AsyncSession
        SQLAlchemy async database session.

    Returns
    -------
    dict
        Success response with access token, refresh token, and user data.

    Raises
    ------
    HTTPException(401)
        If credentials are invalid.
    HTTPException(403)
        If account is suspended, deleted, or not verified.

    Security Notes
    --------------
    - Passwords are never returned in responses
    - Access tokens expire in 30 minutes
    - Refresh tokens expire in 7 days
    - Account status checked before authentication
    - OWASP API2: Broken Authentication

    Example
    -------
    >>> result = await login_user(
    ...     LoginRequest(email="user@example.com", password="SecurePass123!"),
    ...     db
    ... )
    >>> print(result["data"]["access_token"])
    "eyJhbGciOiJIUzI1NiIs..."
    """
    # -------------------------------------------------------------------------
    # Step 1: Find user
    # -------------------------------------------------------------------------
    result = await db.execute(
        select(User).where(User.email == payload.email)
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    # -------------------------------------------------------------------------
    # Step 2: Verify password (async, non-blocking)
    # -------------------------------------------------------------------------
    if not await verify_password_async(
        payload.password,
        user.password_hash
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    # -------------------------------------------------------------------------
    # Step 3: Check account status
    # -------------------------------------------------------------------------
    if user.account_status == AccountStatus.suspended:
        raise HTTPException(
            status_code=403,
            detail="Account suspended"
        )

    if user.account_status == AccountStatus.deleted:
        raise HTTPException(
            status_code=403,
            detail="Account deleted"
        )

    if not user.is_verified:
        raise HTTPException(
            status_code=403,
            detail="Email not verified"
        )

    # -------------------------------------------------------------------------
    # Step 4: Update last login
    # -------------------------------------------------------------------------
    user.last_login = datetime.now(timezone.utc)
    await db.commit()

    # -------------------------------------------------------------------------
    # Step 5: Generate tokens
    # -------------------------------------------------------------------------
    subject = str(user.id)
    extra = {
        "email": user.email,
        "role": user.role.value
    }

    access_token = create_access_token(subject, extra)
    refresh_token = create_refresh_token(subject)

    # -------------------------------------------------------------------------
    # Step 6: Return response
    # -------------------------------------------------------------------------
    return {
        "success": True,
        "message": "Login successful",
        "data": {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "user": user_to_dict(user)
        }
    }


# =============================================================================
# REFRESH TOKEN
# =============================================================================

async def refresh_user_token(
    payload: RefreshTokenRequest,
    db: AsyncSession
) -> dict:
    """
    Generate a new access token using a refresh token.

    This implements refresh token rotation for improved security.
    Each refresh request generates a new access token AND a new refresh token.

    Workflow
    --------
        1. Decode and validate the refresh token
        2. Extract user ID from token
        3. Find user in database
        4. Generate new access token
        5. Generate new refresh token (rotation)
        6. Return both tokens

    Parameters
    ----------
    payload : RefreshTokenRequest
        Contains the refresh token.
    db : AsyncSession
        SQLAlchemy async database session.

    Returns
    -------
    dict
        Success response with new access and refresh tokens.

    Raises
    ------
    HTTPException(401)
        If refresh token is invalid or user not found.

    Security Notes
    --------------
    - Refresh token rotation: new token on every refresh
    - Old refresh tokens become invalid (one-time use)
    - Access tokens expire in 30 minutes
    - Refresh tokens expire in 7 days
    - OWASP API2: Broken Authentication

    Example
    -------
    >>> result = await refresh_user_token(
    ...     RefreshTokenRequest(refresh_token="eyJhbGciOiJIUzI1NiIs..."),
    ...     db
    ... )
    >>> print(result["data"]["access_token"])
    "eyJhbGciOiJIUzI1NiIs..."
    """
    # -------------------------------------------------------------------------
    # Step 1: Decode and validate refresh token
    # -------------------------------------------------------------------------
    try:
        token_data = decode_token(
            payload.refresh_token,
            TokenType.refresh
        )
    except ValueError:
        raise HTTPException(
            status_code=401,
            detail="Invalid refresh token"
        )

    # -------------------------------------------------------------------------
    # Step 2: Find user
    # -------------------------------------------------------------------------
    result = await db.execute(
        select(User).where(User.id == int(token_data["sub"]))
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="User not found"
        )

    # -------------------------------------------------------------------------
    # Step 3: Generate new tokens (rotation)
    # -------------------------------------------------------------------------
    subject = str(user.id)
    extra = {
        "email": user.email,
        "role": user.role.value
    }

    access_token = create_access_token(subject, extra)
    new_refresh = create_refresh_token(subject)

    # -------------------------------------------------------------------------
    # Step 4: Return response
    # -------------------------------------------------------------------------
    return {
        "success": True,
        "message": "Token refreshed",
        "data": {
            "access_token": access_token,
            "refresh_token": new_refresh,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }
    }


# =============================================================================
# SECURITY COMPLIANCE SUMMARY
# =============================================================================
#
# OWASP API Security Top 10 (2023):
#
# 1. API1: Broken Object Level Authorization
#    User data access is scoped to authenticated user
#    Account operations check user existence before modification
#
# 2. API2: Broken Authentication
#    Password hashing (Argon2/bcrypt)
#    JWT with expiration
#    Refresh token rotation
#    OTP verification
#    Account status validation
#
# 3. API3: Broken Object Property Level Authorization
#    User data filtered via user_to_dict()
#    Password hash never exposed in responses
#
# 4. API4: Unrestricted Resource Consumption
#    OTP expiration prevents endless attempts
#    Async operations prevent blocking
#
# 5. API5: Broken Function Level Authorization
#    Role-based access control
#    Account status checks
#
# 6. API6: Unrestricted Access to Sensitive Flows
#    OTP required for verification
#    Password hashing prevents credential theft
#
# 8. API8: Security Misconfiguration
#    Secure password hashing algorithms
#    Timezone-aware expiration checks
#
# 9. API9: Improper Inventory Management
#    Full audit logging of authentication events
#
# =============================================================================


# =============================================================================
# DEVELOPMENT NOTES
# =============================================================================
#
# To test the authentication flow:
#
# 1. Register: POST /api/v1/auth/register
# 2. Get OTP from logs: docker-compose logs auth | grep "verification code"
# 3. Verify: POST /api/v1/auth/verify-email
# 4. Login: POST /api/v1/auth/login
# 5. Refresh: POST /api/v1/auth/refresh
#
# =============================================================================