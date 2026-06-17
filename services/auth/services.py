"""
modules/auth/services.py
================================================================================
Authentication Business Logic Service – CyberSafe Connect
================================================================================

This module contains the core authentication business logic used by the
authentication microservice.

Unlike routes.py, this file contains NO HTTP endpoint definitions.

It centralizes all security-sensitive account operations.

--------------------------------------------------------------------------------
ROLE
--------------------------------------------------------------------------------

This module is responsible for:

    • User registration
    • Password hashing workflow
    • OTP generation workflow
    • Email verification workflow
    • Login authentication workflow
    • JWT token creation
    • Refresh token generation
    • Account status validation

This layer separates business logic from API transport logic.

--------------------------------------------------------------------------------
SECURITY PRINCIPLES
--------------------------------------------------------------------------------

• No password stored in plain text
• Email uniqueness verification
• Account verification before login
• Suspended/deleted account protection
• Secure JWT generation
• OTP expiration enforcement
• Prevent unauthorized account access

================================================================================
"""

from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy.orm import Session

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

from config import ACCESS_TOKEN_EXPIRE_MINUTES


# =============================================================================
# REGISTER USER
# =============================================================================

def register_user(
    payload: RegisterRequest,
    db: Session
) -> dict:
    """
    Register a new user account.

    Process:

        1. Verify email uniqueness
        2. Generate OTP code
        3. Hash password securely
        4. Store account in pending state
        5. Send verification email

    Returns
    -------
    dict
    """

    existing_user = db.query(User).filter(
        User.email == payload.email
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Email already exists"
        )

    code, expires_at = generate_otp()

    user = User(
        fullname=payload.fullname,

        email=payload.email,

        password_hash=hash_password(
            payload.password
        ),

        role=UserRole(payload.role),

        verification_code=code,

        verification_expires_at=expires_at,

        is_verified=False,

        account_status=AccountStatus.pending
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    send_verification_email(
        user.email,
        user.fullname,
        code
    )

    return {
        "success": True,

        "message":
            "Account created successfully. Verify your email.",

        "data": user_to_dict(user)
    }


# =============================================================================
# VERIFY EMAIL
# =============================================================================

def verify_email(
    payload: VerifyEmailRequest,
    db: Session
) -> dict:
    """
    Verify user email using OTP.
    """

    user = db.query(User).filter(
        User.email == payload.email
    ).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="Account not found"
        )

    if user.is_verified:
        return {
            "success": True,
            "message": "Already verified",
            "data": user_to_dict(user)
        }

    if user.verification_code != payload.code:
        raise HTTPException(
            status_code=400,
            detail="Invalid OTP code"
        )

    if (
        user.verification_expires_at and
        user.verification_expires_at <
        datetime.now(timezone.utc)
    ):
        raise HTTPException(
            status_code=400,
            detail="OTP expired"
        )

    user.is_verified = True
    user.account_status = AccountStatus.active
    user.verification_code = None
    user.verification_expires_at = None

    db.commit()
    db.refresh(user)

    return {
        "success": True,
        "message": "Email verified",
        "data": user_to_dict(user)
    }


# =============================================================================
# RESEND OTP
# =============================================================================

def resend_verification(
    payload: ResendVerificationRequest,
    db: Session
) -> dict:
    """
    Generate new verification code.
    """

    user = db.query(User).filter(
        User.email == payload.email
    ).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="Account not found"
        )

    if user.is_verified:
        return {
            "success": True,
            "message": "Already verified"
        }

    code, expires_at = generate_otp()

    user.verification_code = code
    user.verification_expires_at = expires_at

    db.commit()

    send_verification_email(
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

def login_user(
    payload: LoginRequest,
    db: Session
) -> dict:
    """
    Authenticate user credentials.
    """

    user = db.query(User).filter(
        User.email == payload.email
    ).first()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    if not verify_password(
        payload.password,
        user.password_hash
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

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

    user.last_login = datetime.now(
        timezone.utc
    )

    db.commit()

    subject = str(user.id)

    extra = {
        "email": user.email,
        "role": user.role.value
    }

    access_token = create_access_token(
        subject,
        extra
    )

    refresh_token = create_refresh_token(
        subject
    )

    return {
        "success": True,

        "message": "Login successful",

        "data": {
            "access_token": access_token,

            "refresh_token": refresh_token,

            "token_type": "bearer",

            "expires_in":
                ACCESS_TOKEN_EXPIRE_MINUTES * 60,

            "user": user_to_dict(user)
        }
    }


# =============================================================================
# REFRESH TOKEN
# =============================================================================

def refresh_user_token(
    payload: RefreshTokenRequest,
    db: Session
) -> dict:
    """
    Generate new access token using refresh token.
    """

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

    user = db.query(User).filter(
        User.id == int(
            token_data["sub"]
        )
    ).first()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="User not found"
        )

    subject = str(user.id)

    extra = {
        "email": user.email,
        "role": user.role.value
    }

    access_token = create_access_token(
        subject,
        extra
    )

    new_refresh = create_refresh_token(
        subject
    )

    return {
        "success": True,

        "message": "Token refreshed",

        "data": {
            "access_token": access_token,

            "refresh_token": new_refresh,

            "token_type": "bearer",

            "expires_in":
                ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }
    }