"""
modules/auth/models.py
================================================================================
User ORM Model – CyberSafe Connect Auth Service
================================================================================

This module defines the User database model used for authentication and
account management in the CyberSafe Connect platform.

The User model represents authenticated accounts stored inside the
authentication microservice database.

--------------------------------------------------------------------------------
ROLE
--------------------------------------------------------------------------------
The User model is responsible for managing:

    • User identity information (fullname, email)
    • Secure authentication credentials (password hashing)
    • Email verification lifecycle (OTP validation)
    • Account lifecycle management
    • Role-based access control (RBAC)
    • Authentication audit logging
    • Security monitoring and account activity tracking

This model acts as the core persistence layer of the authentication system.

--------------------------------------------------------------------------------
SECURITY DESIGN
--------------------------------------------------------------------------------

This model follows secure authentication principles:

    • Passwords are NEVER stored in plain text
    • Passwords are stored only as cryptographic hashes
    • Email addresses are unique and indexed
    • Invalid roles are blocked at database level using Enum
    • OTP verification is required before account activation
    • Verification codes preserve leading zeros
    • Account lifecycle states are centrally managed
    • Audit timestamps allow suspicious activity monitoring

--------------------------------------------------------------------------------
DATABASE MAPPING
--------------------------------------------------------------------------------

Table: users

Columns:

    id
        Primary key identifier (auto-increment integer)

    fullname
        User full name

    email
        Unique authentication email

    password_hash
        Secure password hash (bcrypt / argon2)

    role
        User role (citizen, company, admin)

    is_verified
        Email verification status

    account_status
        Current account lifecycle status

    verification_code
        OTP verification code

    created_at
        Account creation timestamp

    updated_at
        Last modification timestamp

    last_login
        Last successful login timestamp

--------------------------------------------------------------------------------
ACCOUNT LIFECYCLE
--------------------------------------------------------------------------------

1. User registers

        is_verified = False
        account_status = pending

2. System generates OTP verification code

        verification_code = "492731"

3. User validates OTP

        is_verified = True
        account_status = active

4. User logs in successfully

        last_login updated automatically

5. Administrator may suspend account if suspicious activity detected

        account_status = suspended

--------------------------------------------------------------------------------
SECURITY IMPROVEMENTS IMPLEMENTED
--------------------------------------------------------------------------------

• Centralized role management using UserRole enum
• Centralized account lifecycle management using AccountStatus enum
• Database-level protection against invalid role injection
• Explicit password hash storage size
• Verification code stored as string (preserves leading zeros)
• Timestamp tracking for audit logging
• Account suspension capability for incident response
• Last login monitoring for suspicious behavior detection
• Schema prepared for production deployment and JWT authentication

================================================================================
"""

# =============================================================================
# INTERNAL IMPORTS
# =============================================================================
# Relative imports recommended for package consistency.
# Prevents import errors during package execution.
# =============================================================================
from enums import UserRole, AccountStatus
from database import Base


# =============================================================================
# SQLALCHEMY IMPORTS
# =============================================================================
from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    Enum,
    DateTime
)

from sqlalchemy.sql import func


# =============================================================================
# USER MODEL
# =============================================================================
class User(Base):
    """
    User ORM model representing an authenticated platform account.

    This model stores identity information, authentication credentials,
    account verification state and authorization roles.

    Security principles:

        • Plain-text passwords are never stored
        • Passwords are stored only as secure hashes
        • Roles are validated at database level
        • Account lifecycle is strictly controlled
        • Audit timestamps preserve activity history
        • Suspicious accounts may be suspended
    """

    __tablename__ = "users"

    # -------------------------------------------------------------------------
    # PRIMARY KEY
    #
    # Unique internal identifier for each user.
    # Used by authentication service and foreign key relationships.
    # -------------------------------------------------------------------------
    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    # -------------------------------------------------------------------------
    # USER FULL NAME
    #
    # Stores the legal or public name of the user.
    #
    # Limited size prevents oversized payload abuse.
    #
    # Example:
    #       Jean Pierre Ndzié
    # -------------------------------------------------------------------------
    fullname = Column(
        String(80),
        nullable=False
    )

    # -------------------------------------------------------------------------
    # USER EMAIL ADDRESS
    #
    # Unique authentication identifier.
    #
    # Security:
    #
    #   • Unique constraint prevents duplicate accounts
    #   • Indexed for fast authentication lookup
    #
    # Example:
    #       user@cybersafeconnect.cm
    # -------------------------------------------------------------------------
    email = Column(
        String(255),
        unique=True,
        index=True,
        nullable=False
    )

    # -------------------------------------------------------------------------
    # PASSWORD HASH
    #
    # Stores cryptographic password hash.
    #
    # Supported algorithms:
    #
    #       bcrypt
    #       argon2
    #
    # Password hashing must occur inside security.py
    #
    # Plain-text passwords must NEVER be stored in database.
    #
    # Example:
    #
    #       $2b$12$8zsk...
    # -------------------------------------------------------------------------
    password_hash = Column(
        String(255),
        nullable=False
    )

    # -------------------------------------------------------------------------
    # USER ROLE
    #
    # Role-based access control.
    #
    # Allowed roles defined in UserRole enum:
    #
    #       citizen
    #       company
    #       admin
    #
    # Security rule:
    #
    # Public registration API may only create:
    #
    #       citizen
    #       company
    #
    # Admin accounts must only be created internally.
    # -------------------------------------------------------------------------
    role = Column(
        Enum(UserRole),
        nullable=False,
        default=UserRole.citizen
    )

    # -------------------------------------------------------------------------
    # EMAIL VERIFICATION STATUS
    #
    # Indicates whether the user completed email verification.
    #
    # False after registration.
    # True after OTP validation.
    #
    # Example:
    #
    #       False → newly created account
    #       True  → verified account
    # -------------------------------------------------------------------------
    is_verified = Column(
        Boolean,
        nullable=False,
        default=False
    )

    # -------------------------------------------------------------------------
    # ACCOUNT STATUS
    #
    # Controls account lifecycle independently from email verification.
    #
    # Allowed states:
    #
    #       pending
    #       active
    #       suspended
    #       deleted
    #
    # Example:
    #
    #       verified + suspended = blocked account
    #
    # Security:
    #
    # Suspended users must not authenticate.
    # -------------------------------------------------------------------------
    account_status = Column(
        Enum(AccountStatus),
        nullable=False,
        default=AccountStatus.pending
    )

    # -------------------------------------------------------------------------
    # EMAIL VERIFICATION CODE (OTP)
    #
    # Temporary verification code sent by email.
    #
    # Stored as string instead of integer.
    #
    # Reason:
    #
    #       OTP = 012345
    #
    # Integer conversion would produce:
    #
    #       12345
    #
    # String preserves leading zeros.
    #
    # Supports future alphanumeric OTP:
    #
    #       A7X92P
    # -------------------------------------------------------------------------
    verification_code = Column(
        String(8),
        nullable=True
    )

    verification_expires_at = Column(
        DateTime(timezone=True),
        nullable=True
    )

    # -------------------------------------------------------------------------
    # ACCOUNT CREATION TIMESTAMP
    #
    # Stores account creation date.
    #
    # Used for:
    #
    #       audit logs
    #       suspicious account monitoring
    #       analytics
    #
    # Indexed for fast date filtering.
    # -------------------------------------------------------------------------
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        index=True
    )

    # -------------------------------------------------------------------------
    # LAST UPDATE TIMESTAMP
    #
    # Automatically updated whenever user record changes.
    #
    # Used for:
    #
    #       profile updates
    #       account modifications
    #       security auditing
    # -------------------------------------------------------------------------
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now()
    )

    # -------------------------------------------------------------------------
    # LAST SUCCESSFUL LOGIN
    #
    # Stores the timestamp of the last successful authentication.
    #
    # Used for:
    #
    #       suspicious login detection
    #       dormant account detection
    #       incident response investigation
    #
    # Updated after successful login.
    # -------------------------------------------------------------------------
    last_login = Column(
        DateTime(timezone=True),
        nullable=True
    )