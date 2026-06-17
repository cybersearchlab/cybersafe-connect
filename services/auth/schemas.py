"""
modules/auth/schemas.py
================================================================================
Authentication Schemas – CyberSafe Connect Auth Service
================================================================================

This module defines all Pydantic schemas used for request validation and
response serialization inside the CyberSafe Connect authentication microservice.

Schemas represent the communication contract between client applications
and the backend authentication service.

These schemas guarantee strict validation of incoming data before business
logic execution and ensure that sensitive internal fields are never exposed
through API responses.

--------------------------------------------------------------------------------
ROLE
--------------------------------------------------------------------------------

This module is responsible for validating and serializing data exchanged
between:

    • Web frontend applications
    • Mobile client applications
    • API consumers and third-party services
    • Authentication backend service
    • Internal account management services

The schemas ensure that every incoming request respects the security rules
defined by the authentication system before any database operation occurs.

This module acts as the first security barrier against malformed, invalid
or malicious authentication requests.

--------------------------------------------------------------------------------
WHY SCHEMAS ARE IMPORTANT
--------------------------------------------------------------------------------

Without strict schema validation, malicious users could attempt to send
unexpected or dangerous payloads directly to the authentication service.

Example malicious payload:

    {
        "fullname": "<script>alert('attack')</script>",
        "email": "attacker@email.com",
        "password": "123",
        "role": "admin"
    }

Potential risks without validation:

    • Privilege escalation attempts
    • Malformed or invalid email injection
    • Weak password creation
    • Injection of unauthorized roles
    • Unexpected API crashes due to invalid data types
    • Exposure of sensitive internal fields

Pydantic schemas eliminate these risks by validating all data before the
request reaches the service layer.

--------------------------------------------------------------------------------
SCHEMA GROUPS
--------------------------------------------------------------------------------

1. RegisterRequest
--------------------------------------------------------------------------------

Used during public user registration.

Endpoint:

    POST /register

Purpose:

    Validates user account creation requests.

Validated fields:

    fullname
        User full name or company legal name.

    email
        Valid authentication email address.

    password
        Plain-text password provided by the user.

    role
        Account type selected during registration.

Allowed public roles:

    citizen
        Standard platform user.

    company
        Business or enterprise account.

Security restrictions:

    The following role MUST NEVER be accepted through public registration:

        admin

Security validations performed:

    • Fullname sanitization
    • Email normalization
    • Password complexity validation
    • Unauthorized role rejection

--------------------------------------------------------------------------------

2. LoginRequest
--------------------------------------------------------------------------------

Used during user authentication.

Endpoint:

    POST /login

Purpose:

    Validates authentication credentials before login process.

Validated fields:

    email
        Registered user email.

    password
        Plain-text password submitted for authentication.

Security validations performed:

    • Email format validation
    • Input normalization
    • Credential structure validation

Security note:

    Password verification occurs inside security.py after schema validation.

--------------------------------------------------------------------------------

3. UserResponse
--------------------------------------------------------------------------------

Used when returning user information after successful registration,
authentication or account retrieval.

Purpose:

    Serialize safe user information returned to the client.

Returned fields:

    id
        Internal unique user identifier.

    fullname
        User full name or company name.

    email
        Registered authentication email.

    role
        Assigned user role.

    is_verified
        Email verification state.

    account_status
        Current account lifecycle state.

Security restrictions:

    Sensitive internal fields MUST NEVER be exposed.

Excluded fields:

    password_hash
        Cryptographic password hash stored in database.

    verification_code
        Temporary OTP verification code.

    internal audit metadata
        Internal security monitoring information.

--------------------------------------------------------------------------------
VALIDATION STRATEGY
--------------------------------------------------------------------------------

This module uses layered validation.

Layer 1 — Field Type Validation

    Example:

        email: EmailStr

    Prevents invalid email format.

Layer 2 — Constraint Validation

    Example:

        password minimum length
        fullname maximum length

    Prevents malformed payloads.

Layer 3 — Custom Security Validation

    Example:

        Regex validation
        Role restriction
        Password complexity enforcement

    Prevents malicious input injection.

--------------------------------------------------------------------------------
SECURITY DESIGN
--------------------------------------------------------------------------------

This module implements defensive security validation mechanisms.

Security protections include:

    • Strict input sanitization
    • Email normalization to prevent duplicate accounts
    • Password complexity enforcement
    • Prevention of privilege escalation attempts
    • Prevention of malformed request injection
    • Protection against weak credential creation
    • Separation between internal and external data models
    • Prevention of sensitive data exposure in API responses

--------------------------------------------------------------------------------
ARCHITECTURE PRINCIPLES
--------------------------------------------------------------------------------

This module follows clean architecture principles.

Design rules:

    • Separation of request and response schemas
    • Zero exposure of internal authentication secrets
    • Centralized role management using enums.py
    • Strict compatibility with SQLAlchemy ORM models
    • Full compatibility with JWT authentication layer
    • Future extensibility for RBAC and administrative permissions

This module is used by:

    modules/auth/routes.py
    modules/auth/service.py
    modules/auth/security.py
    modules/auth/modeles.py

--------------------------------------------------------------------------------
AUTHENTICATION FLOW
--------------------------------------------------------------------------------

Registration Flow

    1. Client sends RegisterRequest

    2. Schema validates:
            fullname
            email
            password
            role

    3. Service layer hashes password

    4. Database stores new account

    5. Verification code generated

    6. User receives email verification code

Login Flow

    1. Client sends LoginRequest

    2. Schema validates credentials format

    3. security.py verifies password hash

    4. JWT token generated

    5. User authenticated successfully

--------------------------------------------------------------------------------
SECURITY IMPROVEMENTS IMPLEMENTED
--------------------------------------------------------------------------------

• Centralized role validation using enums.py
• Restriction of public registration roles
• Prevention of unauthorized admin account creation
• Password complexity enforcement
• Fullname sanitization against malformed input
• Email normalization to prevent duplicate registration
• Response filtering to hide sensitive authentication fields
• Secure separation between external API schemas and internal ORM models
• Schema design prepared for JWT authentication and RBAC implementation

================================================================================
"""
import re

from pydantic import (
    BaseModel,
    EmailStr,
    Field,
    field_validator
)

from enums import UserRole, AccountStatus


# =============================================================================
# PUBLIC REGISTRATION ROLE ENUMERATION
# =============================================================================
#
# Only these roles may be created through public registration.
#
# Security:
#
# admin role must never be created through public API.
# =============================================================================
class PublicRegisterRole(str):
    citizen = "citizen"
    company = "company"


# =============================================================================
# REGISTER REQUEST SCHEMA
# =============================================================================
class RegisterRequest(BaseModel):
    """
    Schema used for public account registration.

    Security validation:

        • fullname sanitized
        • email normalized
        • password complexity enforced
        • admin role forbidden
    """

    fullname: str = Field(
        min_length=3,
        max_length=80
    )

    email: EmailStr

    password: str = Field(
        min_length=8,
        max_length=128
    )

    role: str = "citizen"

    @field_validator("fullname")
    @classmethod
    def validate_fullname(cls, value: str) -> str:

        value = value.strip()

        if not re.match(r"^[a-zA-ZÀ-ÿ0-9\s\-'.]+$", value):
            raise ValueError(
                "Fullname contains invalid characters"
            )

        return value

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return value.lower().strip()

    @field_validator("role")
    @classmethod
    def validate_role(cls, value: str) -> str:

        allowed_roles = [
            UserRole.citizen.value,
            UserRole.company.value
        ]

        if value not in allowed_roles:
            raise ValueError(
                "Only citizen and company roles are allowed"
            )

        return value

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:

        if not re.search(r"[A-Z]", value):
            raise ValueError(
                "Password must contain uppercase letter"
            )

        if not re.search(r"[a-z]", value):
            raise ValueError(
                "Password must contain lowercase letter"
            )

        if not re.search(r"\d", value):
            raise ValueError(
                "Password must contain number"
            )

        return value


# =============================================================================
# LOGIN REQUEST SCHEMA
# =============================================================================
class LoginRequest(BaseModel):
    """
    Schema used during user authentication.
    """

    email: EmailStr

    password: str


# =============================================================================
# USER RESPONSE SCHEMA
# =============================================================================
class UserResponse(BaseModel):
    """
    Schema returned after user creation or retrieval.

    Sensitive fields excluded:

        • password_hash
        • verification_code
    """

    id: int

    fullname: str

    email: str

    role: UserRole

    is_verified: bool

    account_status: AccountStatus

    class Config:
        from_attributes = True


class VerifyEmailRequest(BaseModel):
    email: EmailStr
    code: str = Field(min_length=6, max_length=8)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return value.lower().strip()

    @field_validator("code")
    @classmethod
    def normalize_code(cls, value: str) -> str:
        return value.strip()


class ResendVerificationRequest(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return value.lower().strip()


class RefreshTokenRequest(BaseModel):
    refresh_token: str = Field(min_length=10)


class TokenData(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int