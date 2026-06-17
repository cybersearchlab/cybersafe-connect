"""
modules/auth/routes.py
================================================================================
Authentication API Routes – CyberSafe Connect
================================================================================

This module defines all HTTP API endpoints exposed by the authentication
microservice.

Its responsibility is strictly limited to:

    • Receiving HTTP requests
    • Validating request payloads using Pydantic schemas
    • Injecting dependencies
    • Delegating business logic to services.py
    • Returning standardized API responses

--------------------------------------------------------------------------------
ARCHITECTURE ROLE
--------------------------------------------------------------------------------

This module does NOT contain business logic.

Business logic is delegated to:

    services.py

This separation improves:

    • Maintainability
    • Security auditing
    • Unit testing
    • Microservice scalability

--------------------------------------------------------------------------------
SECURITY PRINCIPLES
--------------------------------------------------------------------------------

• All request payloads validated through Pydantic schemas
• Protected routes use JWT authentication dependency
• No direct password handling inside routes
• No direct cryptographic operations inside routes
• Business logic isolated from transport layer

--------------------------------------------------------------------------------
AVAILABLE ENDPOINTS
--------------------------------------------------------------------------------

POST    /register

        Register new account

POST    /verify-email

        Verify account using OTP code

POST    /resend-verification

        Resend verification code

POST    /login

        Authenticate user credentials

POST    /refresh

        Refresh expired access token

GET     /me

        Retrieve authenticated user profile

================================================================================
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from dependencies import (
    get_current_user,
    get_db,
    user_to_dict
)

from models import User

from schemas import (
    LoginRequest,
    RefreshTokenRequest,
    RegisterRequest,
    ResendVerificationRequest,
    VerifyEmailRequest
)

from services import (
    login_user,
    refresh_user_token,
    register_user,
    resend_verification,
    verify_email
)

# =============================================================================
# ROUTER INITIALIZATION
# =============================================================================

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)


# =============================================================================
# REGISTER USER
# =============================================================================

@router.post("/register")
def register(
    payload: RegisterRequest,
    db: Session = Depends(get_db)
):
    """
    Register a new user account.

    Workflow:

        1. Validate request payload
        2. Delegate registration process
        3. Create unverified account
        4. Generate OTP verification code
        5. Return sanitized response

    Returns
    -------
    dict
    """

    return register_user(
        payload=payload,
        db=db
    )


# =============================================================================
# VERIFY EMAIL
# =============================================================================

@router.post("/verify-email")
def verify_email_route(
    payload: VerifyEmailRequest,
    db: Session = Depends(get_db)
):
    """
    Verify account ownership using OTP code.

    Returns
    -------
    dict
    """

    return verify_email(
        payload=payload,
        db=db
    )


# =============================================================================
# RESEND OTP
# =============================================================================

@router.post("/resend-verification")
def resend_verification_route(
    payload: ResendVerificationRequest,
    db: Session = Depends(get_db)
):
    """
    Generate and resend new verification code.

    Returns
    -------
    dict
    """

    return resend_verification(
        payload=payload,
        db=db
    )


# =============================================================================
# LOGIN USER
# =============================================================================

@router.post("/login")
def login(
    payload: LoginRequest,
    db: Session = Depends(get_db)
):
    """
    Authenticate user credentials.

    Returns
    -------
    dict
    """

    return login_user(
        payload=payload,
        db=db
    )


# =============================================================================
# REFRESH TOKEN
# =============================================================================

@router.post("/refresh")
def refresh_token(
    payload: RefreshTokenRequest,
    db: Session = Depends(get_db)
):
    """
    Generate new access token using refresh token.

    Returns
    -------
    dict
    """

    return refresh_user_token(
        payload=payload,
        db=db
    )


# =============================================================================
# CURRENT AUTHENTICATED USER
# =============================================================================

@router.get("/me")
def get_me(
    current_user: User = Depends(get_current_user)
):
    """
    Return authenticated user profile.

    Protected route.

    Requires:

        Authorization: Bearer <access_token>

    Returns
    -------
    dict
    """

    return {
        "success": True,
        "message": "Authenticated user retrieved successfully",
        "data": user_to_dict(current_user)
    }