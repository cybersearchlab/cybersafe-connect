"""
modules/auth/enums.py
================================================================================
Authentication Enumerations – CyberSafe Connect Auth Service
================================================================================

This module defines all authentication-related enumerations used across the
CyberSafe Connect authentication microservice.

Enumerations centralize fixed application constants and prevent duplication
of hardcoded string values across the authentication system.

--------------------------------------------------------------------------------
ROLE
--------------------------------------------------------------------------------
This module is responsible for defining standardized values used by:

    • Request validation schemas (Pydantic)
    • Database ORM models (SQLAlchemy)
    • Authentication service layer
    • JWT token generation and validation
    • Role-based access control (RBAC)
    • Route authorization middleware
    • Future administrative dashboard permissions

By centralizing enumerations, the application avoids inconsistent role
definitions and reduces security risks caused by hardcoded values.

--------------------------------------------------------------------------------
WHY ENUMS ARE IMPORTANT
--------------------------------------------------------------------------------
Without enumerations, developers often write:

    role = "citizen"
    role = "company"
    role = "admin"

across multiple files.

This creates several risks:

    • Typographical errors
          Example: "citisen" instead of "citizen"

    • Inconsistent business logic

    • Privilege escalation vulnerabilities

    • Difficult long-term maintenance

Enums solve this problem by creating a single source of truth.

--------------------------------------------------------------------------------
ENUM GROUPS
--------------------------------------------------------------------------------

1. UserRole
--------------------------------------------------------------------------------
Defines all roles available in the authentication system.

Roles:

    citizen
        Standard public platform user.

        Permissions:
            • Scam detection access
            • Cybersecurity academy access
            • Incident reporting
            • AI assistant access

    company
        Registered business account.

        Permissions:
            • CVE monitoring
            • Security alerts dashboard
            • Business cybersecurity reports
            • Infrastructure monitoring

    admin
        Internal system administrator.

        Permissions:
            • User management
            • Platform moderation
            • Incident investigation
            • Administrative dashboard

Security note:
    The "admin" role MUST NEVER be created through the public registration API.

    Admin accounts must be created manually by system maintainers.

--------------------------------------------------------------------------------

2. AccountStatus
--------------------------------------------------------------------------------
Defines account lifecycle states.

States:

    pending
        User registered but email verification is incomplete.

    active
        User completed verification and account is operational.

    suspended
        Account temporarily blocked by administrator.

    deleted
        Account deactivated or permanently removed.

Security note:
    Suspended users should not be allowed to authenticate.

--------------------------------------------------------------------------------

3. TokenType
--------------------------------------------------------------------------------
Defines JWT authentication token categories.

Types:

    access
        Short-lived token used for API authentication.

    refresh
        Long-lived token used for renewing expired access tokens.

Security note:
    Access and refresh tokens must never share the same expiration policy.

--------------------------------------------------------------------------------
SECURITY DESIGN
--------------------------------------------------------------------------------

This module improves security by:

    • Preventing privilege escalation attacks
    • Eliminating unauthorized role injection
    • Enforcing strict RBAC consistency
    • Preventing hardcoded authentication logic errors
    • Preparing the platform for future access-control expansion

--------------------------------------------------------------------------------
ARCHITECTURE BENEFITS
--------------------------------------------------------------------------------

This module is imported by:

    modules/auth/schemas.py
    modules/auth/modeles.py
    modules/auth/security.py
    modules/auth/service.py
    modules/auth/routes.py

This guarantees a single consistent authentication model across the entire
microservice.

================================================================================
"""

from enum import Enum


# =============================================================================
# USER ROLE ENUMERATION
# =============================================================================
class UserRole(str, Enum):
    """
    Defines all roles supported by the authentication system.

    Roles
    -----

    citizen
        Standard user account for public platform access.

    company
        Business account for cybersecurity monitoring services.

    admin
        Internal administrator account.

    Security
    --------
    Only 'citizen' and 'company' may be created through public registration.

    'admin' accounts must only be created internally by system administrators.
    """

    citizen = "citizen"

    company = "company"

    admin = "admin"


# =============================================================================
# ACCOUNT STATUS ENUMERATION
# =============================================================================
class AccountStatus(str, Enum):
    """
    Defines account lifecycle states.

    States
    ------

    pending
        Account created but email not verified.

    active
        Account fully verified and operational.

    suspended
        Account blocked temporarily by administrator.

    deleted
        Account removed or permanently disabled.

    Security
    --------
    Suspended and deleted accounts must not access protected resources.
    """

    pending = "pending"

    active = "active"

    suspended = "suspended"

    deleted = "deleted"


# =============================================================================
# TOKEN TYPE ENUMERATION
# =============================================================================
class TokenType(str, Enum):
    """
    Defines JWT token categories used by the authentication service.

    Types
    -----

    access
        Short-lived token used for API authorization.

    refresh
        Long-lived token used to generate new access tokens.

    Security
    --------
    Access and refresh tokens must use different expiration durations.
    """

    access = "access"

    refresh = "refresh"