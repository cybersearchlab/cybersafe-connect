"""
================================================================================
MODULE: config.py
================================================================================

CyberSafe Connect - Authentication Service Configuration
================================================================================

OVERVIEW
--------

This module serves as the central configuration hub for the authentication
microservice. It loads, validates, and exposes all runtime configuration
settings from environment variables and the .env file.

ARCHITECTURE CONTEXT
--------------------

This module is the SINGLE SOURCE OF TRUTH for all configuration across
the authentication service. All other modules import configuration from here.

    ┌─────────────────────────────────────────────────────────────────────────┐
    │                         .env File                                       │
    │  ┌─────────────────────────────────────────────────────────────────┐    │
    │  │  JWT_SECRET_KEY=...                                             │    │
    │  │  DATABASE_URL=postgresql://...                                  │    │
    │  │  ALLOWED_ORIGINS=http://localhost:3000                          │    │
    │  └─────────────────────────────────────────────────────────────────┘    │
    │                                   │                                     │
    │                                   ▼                                     │
    │  ┌─────────────────────────────────────────────────────────────────┐    │
    │  │                     config.py                                   │    │
    │  │  (Load, Validate, Expose)                                       │    │
    │  └─────────────────────────────────────────────────────────────────┘    │
    │                                   │                                     │
    │         ┌─────────────────────────┼─────────────────────────┐           │
    │         │                         │                         │           │
    │         ▼                         ▼                         ▼           │
    │  ┌──────────────┐          ┌──────────────┐          ┌──────────────┐   │
    │  │   app.py     │          │  security.py │          │ database.py  │   │
    │  │  (FastAPI)   │          │    (JWT)     │          │ (SQLAlchemy) │   │
    │  └──────────────┘          └──────────────┘          └──────────────┘   │
    └─────────────────────────────────────────────────────────────────────────┘

INTERACTIONS WITH OTHER MODULES
-------------------------------

| Module           | Configuration Used                                      |
|------------------|---------------------------------------------------------|
| app.py           | ENVIRONMENT, PORT, DEBUG, ALLOWED_ORIGINS, ALLOWED_HOSTS|
| security.py      | JWT_SECRET_KEY, JWT_ALGORITHM, ACCESS_TOKEN_EXPIRE_*    |
| database.py      | DATABASE_URL, DATABASE_POOL_SIZE, DATABASE_ECHO         |
| email_service.py | SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD          |

SECURITY BOUNDARIES
-------------------

This module is the GATEKEEPER of security-sensitive configuration:

1. JWT Secret Validation
   - Must exist (fail-fast if missing)
   - Must be strong (≥ 32 chars, ≥ 64 in production)
   - Invalid in production if weak

2. Environment Validation
   - Development: Permissive (SQLite allowed, weak secrets allowed)
   - Production: Strict (SQLite forbidden, strong secrets required)

3. CORS Validation
   - Wildcard "*" is FORBIDDEN
   - Only specific origins allowed

4. Fail-Fast Philosophy
   - Service fails to start if configuration is invalid
   - Prevents running in an insecure state

CONFIGURATION DOMAINS
---------------------

| Domain          | Variables                          | Purpose                       |
|-----------------|------------------------------------|-------------------------------|
| Environment     | ENVIRONMENT, PORT, DEBUG           | Runtime context               |
| Database        | DATABASE_URL                       | PostgreSQL/SQLite connection  |
| Database Pool   | DATABASE_POOL_SIZE                 | Connection pool management    |
| JWT Security    | JWT_SECRET_KEY, JWT_ALGORITHM      | Token creation/validation     |
| Token Lifetime  | ACCESS_TOKEN_EXPIRE_MINUTES        | Access token duration         |
| Token Lifetime  | REFRESH_TOKEN_EXPIRE_DAYS          | Refresh token duration        |
| OTP             | OTP_EXPIRE_MINUTES                 | One-time password lifetime    |
| CORS            | ALLOWED_ORIGINS                    | Cross-origin restrictions     |
| Host Security   | ALLOWED_HOSTS                      | Trusted Host validation       |
| Email           | SMTP_HOST, SMTP_USER, SMTP_PASSWORD| Email delivery                |
| Redis (Future)  | REDIS_HOST, REDIS_PORT             | Token blacklist cache         |

================================================================================
ENVIRONMENT VARIABLES REFERENCE
================================================================================

Required in Production:
------------------------
| Variable               | Description                    | Example                          |
|------------------------|--------------------------------|----------------------------------|
| ENVIRONMENT            | Runtime context                | "production"                     |
| JWT_SECRET_KEY         | JWT signing key (≥64 chars)    | "a-very-long-secret-key..."      |
| DATABASE_URL           | PostgreSQL connection string   | "postgresql://user:pass@host/db" |

Required for Email:
-------------------
| Variable               | Description                    | Example                        |
|------------------------|--------------------------------|--------------------------------|
| SMTP_HOST              | SMTP server hostname           | "smtp.gmail.com"               |
| SMTP_USER              | SMTP authentication user       | "noreply@cybersafeconnect.com" |
| SMTP_PASSWORD          | SMTP password/app password     | "your-app-password"            |

Optional (with defaults):
-------------------------
| Variable                    | Default                        | Description                            |
|-----------------------------|--------------------------------|----------------------------------------|
| PORT                        | 8001                           | Service port                           |
| ACCESS_TOKEN_EXPIRE_MINUTES | 30                             | Access token lifetime                  |
| REFRESH_TOKEN_EXPIRE_DAYS   | 7                              | Refresh token lifetime                 |
| ALLOWED_ORIGINS             | http://localhost:3000          | CORS allowed origins (comma separated) |
| SMTP_PORT                   | 587                            | SMTP port                              |

================================================================================
FAILURE MODES
================================================================================

| Failure Mode                | Impact                     | Recovery                        |
|-----------------------------|----------------------------|---------------------------------|
| JWT_SECRET_KEY missing      | Service CRASHES            | Set in .env file                |
| JWT_SECRET_KEY weak         | Service CRASHES (prod)     | Use strong secret (≥64 chars)   |
| SQLite in production        | Service CRASHES            | Use PostgreSQL                  |
| DATABASE_URL invalid        | Service fails at startup   | Fix connection string           |
| ALLOWED_ORIGINS empty       | CORS errors                | Configure allowed origins       |
| Wildcard "*" in CORS        | Service CRASHES            | Use specific origins            |

================================================================================
OWASP API SECURITY TOP 10 (2023) COMPLIANCE
================================================================================

| #   | Category                               | Status  | Implementation                     |
|-----|----------------------------------------|---------|------------------------------------|
| 1   | Broken Object Level Authorization      | N/A     | Configuration only                 |
| 2   | Broken Authentication                  | yes     | JWT_SECRET_KEY validation          |
| 3   | Broken Object Property Level Auth      | N/A     | Configuration only                 |
| 4   | Unrestricted Resource Consumption      | yes     | DATABASE_POOL_SIZE, POOL_TIMEOUT   |
| 5   | Broken Function Level Authorization    | N/A     | Configuration only                 |
| 6   | Unrestricted Access to Sensitive Flows | yes     | OTP_EXPIRE_MINUTES                 |
| 7   | Server Side Request Forgery            | N/A     | Configuration only                 |
| 8   | Security Misconfiguration              | yes     | Environment, CORS, Debug validation|
| 9   | Improper Inventory Management          | yes     | Centralized configuration          |
| 10  | Unsafe Consumption of APIs             | N/A     | Configuration only                 |

================================================================================
DEVELOPER NOTES
================================================================================

For local development:
1. Copy .env.example to .env
2. Set JWT_SECRET_KEY (you can use: openssl rand -hex 32)
3. Set DATABASE_URL to SQLite or PostgreSQL

For production:
1. Use a STRONG JWT_SECRET_KEY (at least 64 chars)
2. Use PostgreSQL ONLY (SQLite is forbidden)
3. Set specific ALLOWED_ORIGINS (never "*")
4. Configure SMTP for email verification
5. Set ENVIRONMENT=production

================================================================================
"""

import os
from typing import List, Optional

from dotenv import load_dotenv
from pydantic import Field, ValidationError, field_validator
from pydantic_settings import BaseSettings

# =============================================================================
# ENVIRONMENT LOADING
# =============================================================================

load_dotenv()


# =============================================================================
# SETTINGS MODEL (Pydantic)
# =============================================================================

class Settings(BaseSettings):
    """
    Application settings loaded from environment variables with validation.
    """

    # =========================================================================
    # Application
    # =========================================================================

    ENVIRONMENT: str = Field(
        default="development",
        description="Runtime environment: development, staging, production"
    )

    PORT: int = Field(
        default=8001,
        description="Port the service listens on",
        ge=1,
        le=65535
    )

    DEBUG: bool = Field(
        default=True,
        description="Enable debug mode (verbose logging)"
    )

    # =========================================================================
    # Security - JWT
    # =========================================================================

    JWT_SECRET_KEY: Optional[str] = Field(
        default=None,
        description="JWT signing key (MUST be strong in production)"
    )

    JWT_ALGORITHM: str = Field(
        default="HS256",
        description="JWT signing algorithm"
    )

    JWT_ISSUER: str = Field(
        default="cybersafe-auth",
        description="JWT issuer claim"
    )

    JWT_AUDIENCE: str = Field(
        default="cybersafe-services",
        description="JWT audience claim"
    )

    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(
        default=30,
        description="Access token lifetime in minutes",
        ge=1,
        le=1440
    )

    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(
        default=7,
        description="Refresh token lifetime in days",
        ge=1,
        le=90
    )

    # =========================================================================
    # Security - OTP
    # =========================================================================

    OTP_EXPIRE_MINUTES: int = Field(
        default=15,
        description="OTP code lifetime in minutes",
        ge=1,
        le=60
    )

    # =========================================================================
    # Database
    # =========================================================================

    DATABASE_URL: str = Field(
        default="sqlite:///./data/users.db",
        description="Database connection string"
    )

    DATABASE_POOL_SIZE: int = Field(
        default=5,
        description="Database connection pool size",
        ge=1,
        le=50
    )

    DATABASE_MAX_OVERFLOW: int = Field(
        default=10,
        description="Maximum extra connections in pool",
        ge=0,
        le=50
    )

    DATABASE_POOL_TIMEOUT: int = Field(
        default=30,
        description="Connection pool timeout in seconds",
        ge=1,
        le=60
    )

    DATABASE_ECHO: bool = Field(
        default=False,
        description="Log all SQL queries (development only)"
    )

    # =========================================================================
    # CORS
    # =========================================================================

    ALLOWED_ORIGINS: List[str] = Field(
        default=["http://localhost:3000"],
        description="Allowed CORS origins (comma-separated in env)"
    )

    # =========================================================================
    # Host Security
    # =========================================================================

    ALLOWED_HOSTS: List[str] = Field(
        default=["localhost", "127.0.0.1"],
        description="Allowed Host headers"
    )

    # =========================================================================
    # Email (SMTP)
    # =========================================================================

    SMTP_HOST: Optional[str] = Field(
        default=None,
        description="SMTP server hostname"
    )

    SMTP_PORT: int = Field(
        default=587,
        description="SMTP server port",
        ge=1,
        le=65535
    )

    SMTP_USER: Optional[str] = Field(
        default=None,
        description="SMTP authentication username"
    )

    SMTP_PASSWORD: Optional[str] = Field(
        default=None,
        description="SMTP authentication password"
    )

    SMTP_TLS: bool = Field(
        default=True,
        description="Enable STARTTLS for SMTP"
    )

    EMAIL_FROM: str = Field(
        default="noreply@cybersafeconnect.com",
        description="From address for outgoing emails"
    )

    # =========================================================================
    # Redis
    # =========================================================================

    REDIS_HOST: str = Field(
        default="redis",
        description="Redis server hostname"
    )

    REDIS_PORT: int = Field(
        default=6379,
        description="Redis server port",
        ge=1,
        le=65535
    )

    REDIS_DB: int = Field(
        default=0,
        description="Redis database number",
        ge=0,
        le=15
    )

    REDIS_PASSWORD: Optional[str] = Field(
        default=None,
        description="Redis password (if required)"
    )

    # =========================================================================
    # Validators
    # =========================================================================

    @field_validator("ENVIRONMENT")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        allowed = ["development", "staging", "production"]
        if v not in allowed:
            raise ValueError(
                f"ENVIRONMENT must be one of: {', '.join(allowed)}. "
                f"Received: {v}"
            )
        return v

    @field_validator("JWT_SECRET_KEY")
    @classmethod
    def validate_jwt_secret(cls, v: Optional[str], info) -> str:
        if v is None:
            raise ValueError(
                "JWT_SECRET_KEY is required. "
                "Generate one with: openssl rand -hex 32"
            )

        if len(v) < 32:
            raise ValueError(
                f"JWT_SECRET_KEY must be at least 32 characters. "
                f"Current length: {len(v)}"
            )

        environment = info.data.get("ENVIRONMENT", "development")
        if environment in ["staging", "production"] and len(v) < 64:
            raise ValueError(
                f"JWT_SECRET_KEY must be at least 64 characters in {environment}. "
                f"Current length: {len(v)}"
            )

        return v

    @field_validator("DATABASE_URL")
    @classmethod
    def validate_database_url(cls, v: str, info) -> str:
        environment = info.data.get("ENVIRONMENT", "development")
        if environment == "production" and v.startswith("sqlite"):
            raise ValueError(
                "SQLite is FORBIDDEN in production. "
                "Use PostgreSQL: postgresql://user:password@host/dbname"
            )
        return v

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def parse_allowed_origins(cls, v) -> List[str]:
        if isinstance(v, str):
            origins = [origin.strip() for origin in v.split(",") if origin.strip()]
        elif isinstance(v, list):
            origins = v
        else:
            origins = []

        for origin in origins:
            if origin == "*":
                raise ValueError(
                    "Wildcard '*' is NOT allowed for ALLOWED_ORIGINS for security reasons. "
                    "Specify exact origins: http://localhost:3000,https://cybersafeconnect.com"
                )

        return origins

    @field_validator("ALLOWED_HOSTS", mode="before")
    @classmethod
    def parse_allowed_hosts(cls, v) -> List[str]:
        if isinstance(v, str):
            return [host.strip() for host in v.split(",") if host.strip()]
        elif isinstance(v, list):
            return v
        return []

    @field_validator("DEBUG")
    @classmethod
    def validate_debug(cls, v: bool, info) -> bool:
        environment = info.data.get("ENVIRONMENT", "development")
        if environment == "production" and v:
            raise ValueError(
                "DEBUG mode MUST be disabled in production. "
                "Set DEBUG=false in production"
            )
        return v

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True
        extra = "ignore"


# =============================================================================
# LOAD SETTINGS
# =============================================================================

def load_settings() -> Settings:
    try:
        return Settings()
    except ValidationError as e:
        print("=" * 80)
        print(" CONFIGURATION ERROR: Invalid settings")
        print("=" * 80)
        for error in e.errors():
            location = " -> ".join(str(loc) for loc in error["loc"])
            print(f"  • {location}: {error['msg']}")
        print("=" * 80)
        print("Please fix the configuration and restart the service.")
        print("=" * 80)
        raise


settings = load_settings()


# =============================================================================
# EXPORT VARIABLES
# =============================================================================

# Application
ENVIRONMENT = settings.ENVIRONMENT
PORT = settings.PORT
DEBUG = settings.DEBUG

# Security - JWT
JWT_SECRET_KEY = settings.JWT_SECRET_KEY
JWT_ALGORITHM = settings.JWT_ALGORITHM
JWT_ISSUER = settings.JWT_ISSUER
JWT_AUDIENCE = settings.JWT_AUDIENCE
ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES
REFRESH_TOKEN_EXPIRE_DAYS = settings.REFRESH_TOKEN_EXPIRE_DAYS

# Security - OTP
OTP_EXPIRE_MINUTES = settings.OTP_EXPIRE_MINUTES

# Database
DATABASE_URL = settings.DATABASE_URL
DATABASE_POOL_SIZE = settings.DATABASE_POOL_SIZE
DATABASE_MAX_OVERFLOW = settings.DATABASE_MAX_OVERFLOW
DATABASE_POOL_TIMEOUT = settings.DATABASE_POOL_TIMEOUT
DATABASE_ECHO = settings.DATABASE_ECHO

# CORS
ALLOWED_ORIGINS = settings.ALLOWED_ORIGINS
ALLOWED_HOSTS = settings.ALLOWED_HOSTS

# Email
SMTP_HOST = settings.SMTP_HOST
SMTP_PORT = settings.SMTP_PORT
SMTP_USER = settings.SMTP_USER
SMTP_PASSWORD = settings.SMTP_PASSWORD
SMTP_TLS = settings.SMTP_TLS
EMAIL_FROM = settings.EMAIL_FROM

# Redis
REDIS_HOST = settings.REDIS_HOST
REDIS_PORT = settings.REDIS_PORT
REDIS_DB = settings.REDIS_DB
REDIS_PASSWORD = settings.REDIS_PASSWORD

# Aliases
SECRET_KEY = JWT_SECRET_KEY
ALGORITHM = JWT_ALGORITHM


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def is_development() -> bool:
    """Return True if running in development environment."""
    return ENVIRONMENT == "development"


def is_staging() -> bool:
    """Return True if running in staging environment."""
    return ENVIRONMENT == "staging"


def is_production() -> bool:
    """Return True if running in production environment."""
    return ENVIRONMENT == "production"


def is_debug_enabled() -> bool:
    """Return True if debug mode is enabled."""
    return DEBUG and is_development()


# =============================================================================
# CONFIGURATION SUMMARY
# =============================================================================

def print_config_summary() -> None:
    """Print a summary of the current configuration."""
    print("=" * 80)
    print(" CONFIGURATION SUMMARY")
    print("=" * 80)
    print(f"  Environment:      {ENVIRONMENT}")
    print(f"  Port:             {PORT}")
    print(f"  Debug Mode:       {DEBUG}")
    print(f"  Database:         {DATABASE_URL[:40]}...")
    print(f"  CORS Origins:     {ALLOWED_ORIGINS}")
    print(f"  Allowed Hosts:    {ALLOWED_HOSTS}")
    print(f"  JWT Algorithm:    {JWT_ALGORITHM}")
    print(f"  JWT Secret:       {'*' * 8} (length: {len(JWT_SECRET_KEY)})")
    print(f"  Access Token:     {ACCESS_TOKEN_EXPIRE_MINUTES} minutes")
    print(f"  Refresh Token:    {REFRESH_TOKEN_EXPIRE_DAYS} days")
    print(f"  OTP Expiration:   {OTP_EXPIRE_MINUTES} minutes")
    print(f"  SMTP Enabled:     {bool(SMTP_HOST)}")
    print(f"  Redis Enabled:    {bool(REDIS_HOST)}")
    print("=" * 80)


# =============================================================================
# MAIN (for testing)
# =============================================================================

if __name__ == "__main__":
    print_config_summary()
    print("\n Configuration loaded successfully!")
    print(f"   Environment: {ENVIRONMENT}")
    print(f"   JWT Secret: {'*' * 10} (valid)")
    print(f"   Database: {'ok' if DATABASE_URL else 'missing'}")
    print("\n  All settings validated successfully.")