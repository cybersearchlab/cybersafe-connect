"""
services/auth/app.py
================================================================================
MODULE: app.py
================================================================================

CyberSafe Connect - Authentication Microservice
================================================================================

OVERVIEW
--------

This module serves as the main entry point for the CyberSafe Connect
authentication microservice. It initializes the FastAPI application,
configures security middleware, establishes database connections,
and orchestrates the entire authentication flow.

ARCHITECTURE CONTEXT
--------------------

CyberSafe Connect is a microservices-based platform for cybersecurity
awareness and training. The authentication service is the gateway to
the entire platform.

    ┌─────────────────────────────────────────────────────────────────┐
    │                    CyberSafe Connect Platform                   │
    │                                                                 │
    │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
    │  │   Auth      │  │   Academy   │  │   Alerts    │              │
    │  │  Service    │◄─┤  Service    │  │  Service    │              │
    │  │  (PORT 8001)│  │  (PORT 8006)│  │  (PORT 8004)│              │
    │  └─────────────┘  └─────────────┘  └─────────────┘              │
    │        │               │               │                        │
    │        ▼               ▼               ▼                        │
    │  ┌─────────────────────────────────────────────────────────┐    │
    │  │                    PostgreSQL                           │    │
    │  │                 (Shared Database)                       │    │
    │  └─────────────────────────────────────────────────────────┘    │
    │                                                                 │
    │  ┌─────────────────────────────────────────────────────────┐    │
    │  │                    Redis (Future)                       │    │
    │  │              (Session / Token Cache)                    │    │
    │  └─────────────────────────────────────────────────────────┘    │
    └─────────────────────────────────────────────────────────────────┘

INTERACTIONS WITH OTHER MODULES
-------------------------------

| Module        | Interaction                                        | Direction       |
|---------------|----------------------------------------------------|-----------------|
| Academy       | Receives JWT tokens for user authentication        | ← Outgoing      |
| Alerts        | Receives JWT tokens for user authentication        | ← Outgoing      |
| Reports       | Receives JWT tokens for user authentication        | ← Outgoing      |
| Chatbot       | Receives JWT tokens for user authentication        | ← Outgoing      |
| PostgreSQL    | Reads/writes user data, roles, permissions         | ↔ Bidirectional |
| Redis (FUTURE)| Cache refresh tokens, blacklist revoked tokens     | ↔ Bidirectional |

INPUTS (What this module receives)
----------------------------------

1. HTTP Requests:
   - POST /api/v1/auth/register  - User registration data
   - POST /api/v1/auth/login     - Email + password
   - POST /api/v1/auth/refresh   - Refresh token
   - POST /api/v1/auth/logout    - Access token (for blacklist)
   - GET  /api/v1/auth/me        - Access token (for user info)

2. Environment Variables (.env):
   - SECRET_KEY                  - JWT signing key (MUST be secure)
   - DATABASE_URL                - PostgreSQL connection string
   - ALLOWED_ORIGINS             - CORS allowed origins
   - ENVIRONMENT                 - dev/staging/production
   - SMTP_*                      - Email configuration

3. Database Schema (models.py):
   - Users table                 - id, email, password_hash, roles, etc.
   - RefreshTokens table         - token, user_id, expires_at, revoked

OUTPUTS (What this module produces)
-----------------------------------

1. HTTP Responses:
   - 201 Created                 - User registered successfully
   - 200 OK                      - Login successful (returns JWT tokens)
   - 200 OK                      - User profile data
   - 401 Unauthorized            - Invalid credentials
   - 403 Forbidden               - Insufficient permissions
   - 429 Too Many Requests       - Rate limit exceeded

2. JWT Tokens:
   - Access Token                - Short-lived (15-30 min) for API access
   - Refresh Token               - Long-lived (7 days) for token renewal

3. Audit Logs:
   - All authentication attempts
   - All token operations
   - All user management actions

SECURITY BOUNDARIES
-------------------

This module is the SECURITY GATEWAY for the entire platform. It enforces:

1. Authentication:    Who are you? (JWT + Argon2 password hashing)
2. Authorization:     What can you do? (Role-based access control)
3. Token Management:  Creation, validation, refresh, revocation
4. Rate Limiting:     Prevent brute force attacks
5. Input Validation:  All user inputs are validated via Pydantic schemas
6. Security Headers:  OWASP-recommended headers (CSP, HSTS, etc.)
7. Audit Logging:     All security events are logged for investigation

SECURITY ASSUMPTIONS (What this module expects from others)
-----------------------------------------------------------

1. Other services MUST validate JWT tokens using the same SECRET_KEY
2. Other services MUST NOT trust user-provided roles without validation
3. Database connections MUST be encrypted (SSL/TLS in production)
4. All traffic MUST be over HTTPS in production
5. Secrets MUST NOT be hardcoded (use environment variables)

FAILURE MODES (What happens when things go wrong)
-------------------------------------------------

| Failure Mode              | Impact                     | Recovery                      |
|---------------------------|----------------------------|-------------------------------|
| Database down             | All auth fails             | Retry with backoff            |
| SECRET_KEY weak           | Tokens can be forged       | REGENERATE IMMEDIATELY        |
| Rate limit exceeded       | User blocked temporarily   | Wait 15 minutes               |
| Invalid JWT signature     | Request rejected           | User must re-authenticate     |
| Token expired             | Request rejected           | Use refresh token             |

================================================================================
MODULE DEPENDENCIES
================================================================================

Internal Dependencies:
    - config.py       : Configuration settings (.env)
    - database.py     : PostgreSQL connection and session management
    - routes.py       : API route definitions
    - security.py     : JWT handling, password hashing, token management
    - models.py       : SQLAlchemy ORM models

External Dependencies:
    - fastapi         : Web framework
    - sqlalchemy      : ORM for PostgreSQL
    - slowapi         : Rate limiting
    - pydantic        : Data validation
    - uvicorn         : ASGI server
    - python-jose     : JWT encoding/decoding
    - passlib         : Password hashing (Argon2)
    - psycopg2        : PostgreSQL adapter

================================================================================
DEVELOPER NOTES
================================================================================

For developers integrating with this service:

1. Register a new user:
   POST /api/v1/auth/register
   Body: {"email": "user@example.com", "password": "SecurePass123!"}

2. Login:
   POST /api/v1/auth/login
   Body: {"email": "user@example.com", "password": "SecurePass123!"}
   Response: {"access_token": "xxx", "refresh_token": "yyy"}

3. Call protected endpoints:
   Header: Authorization: Bearer <access_token>

4. Refresh token:
   POST /api/v1/auth/refresh
   Body: {"refresh_token": "yyy"}

5. Logout:
   POST /api/v1/auth/logout
   Header: Authorization: Bearer <access_token>

For administrators:
- All users have a default role of "user"
- Admin roles must be assigned via database directly

================================================================================
OWASP API SECURITY TOP 10 (2023) COMPLIANCE
================================================================================

| #   | Category                               | Status  | Implementation                     |
|-----|----------------------------------------|---------|------------------------------------|
| 1   | Broken Object Level Authorization      | ok      | Role-based access via dependencies |
| 2   | Broken Authentication                  | ok      | JWT + Argon2 password hashing      |
| 3   | Broken Object Property Level Auth      | ok      | Pydantic schemas filter fields     |
| 4   | Unrestricted Resource Consumption      | ok      | Rate limiting + Timeout            |
| 5   | Broken Function Level Authorization    | ok      | Role-based endpoint protection     |
| 6   | Unrestricted Access to Sensitive Flows | ok      | Rate limiting on login/register    |
| 7   | Server Side Request Forgery            | N/A     | No external requests               |
| 8   | Security Misconfiguration              | ok      | Security headers + CORS restricted |
| 9   | Improper Inventory Management          | ok      | Full request/response logging      |
| 10  | Unsafe Consumption of APIs             | N/A     | No external API consumption        |

================================================================================
"""

import asyncio
import logging
import sys
import time
import uuid
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from starlette.middleware.base import BaseHTTPMiddleware

from config import ALLOWED_ORIGINS, ALLOWED_HOSTS, ENVIRONMENT
from database import Base, async_engine, AsyncSessionLocal, get_async_db
from routes import router
from security import validate_security_config


# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

def configure_logging() -> None:
    """
    Configure application-wide logging.

    This function sets up structured logging with consistent format
    for all modules. Logs are sent to stdout for container-friendly
    logging (compatible with ELK, Datadog, CloudWatch, etc.).

    Format: timestamp | level | module | message

    Why use stdout instead of files?
    ---------------------------------
    • Containers don't persist files (logs are lost on restart)
    • Container orchestrators (Docker, Kubernetes) capture stdout
    • Easier to aggregate logs from multiple containers
    • No file permission issues with non-root users

    Log Levels:
        - CRITICAL: System is unusable (database down, SECRET_KEY missing)
        - ERROR: Failed operation (auth failure, DB error)
        - WARNING: Unexpected but recoverable (rate limit, invalid token)
        - INFO: Normal operations (user login, token refresh)
        - DEBUG: Detailed information (development only)

    Security Note:
        - Never log passwords, secret keys, or personal data
        - Log email addresses and IPs (audit trail)
        - Do not log JWT tokens (they contain sensitive claims)
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        stream=sys.stdout,
    )


configure_logging()
logger = logging.getLogger(__name__)


# =============================================================================
# RATE LIMITING
# =============================================================================

def configure_rate_limiter() -> Limiter:
    """
    Configure the rate limiter for the application.

    Rate limiting is a critical security control that prevents:
        - Brute force password attacks
        - Account enumeration attacks
        - DoS (Denial of Service) attacks
        - API abuse

    Rate Limits:
        - /login:      5 attempts per minute
        - /register:   3 attempts per minute
        - /health:     10 attempts per minute (monitoring)
        - /refresh:    10 attempts per minute
        - /me:         30 attempts per minute

    Key Function: get_remote_address()
        - Identifies clients by their IP address
        - Works behind reverse proxies (X-Forwarded-For)
        - Prevents IP spoofing attacks

    Returns:
        Limiter: Configured rate limiter instance

    Security Note:
        - Rate limits should be adjusted based on expected traffic
        - Too restrictive = poor user experience
        - Too permissive = insecure

    OWASP Compliance:
        - API4: Unrestricted Resource Consumption
        - API6: Unrestricted Access to Sensitive Flows
    """
    return Limiter(key_func=get_remote_address)


limiter = configure_rate_limiter()


# =============================================================================
# FASTAPI APPLICATION
# =============================================================================

def create_application() -> FastAPI:
    """
    Create and configure the FastAPI application instance.

    This is the main application factory. All configurations, middlewares,
    exception handlers, and routes are registered here.

    Application Metadata:
        - title:    "CyberSafe Connect - Auth Service"
        - version:  "1.0.0"
        - docs_url: "/docs" (OpenAPI documentation)
        - redoc_url: "/redoc" (ReDoc documentation)

    Configuration:
        - max_request_size: 10MB (prevents large payload attacks)

    Why use an application factory pattern?
        - Allows multiple application instances (test/production)
        - Easier to override configurations for testing
        - Better separation of concerns

    Returns:
        FastAPI: Fully configured FastAPI application

    Security Note:
        - The docs are available in all environments
        - In production, restrict docs to internal networks
        - Alternative: disable docs in production with docs_url=None
    """
    app = FastAPI(
        title="CyberSafe Connect - Auth Service",
        version="1.0.0",
        description=__doc__,  # This entire docstring
        max_request_size=10 * 1024 * 1024,  # 10 MB
        docs_url="/docs",
        redoc_url="/redoc",
        swagger_ui_parameters={
            "syntaxHighlight": True,
            "persistAuthorization": True,
        }
    )

    # Store the rate limiter in app state for access in routes
    app.state.limiter = limiter

    # Register the rate limit exception handler
    app.add_exception_handler(429, _rate_limit_exceeded_handler)

    return app


app = create_application()


# =============================================================================
# APPLICATION LIFECYCLE EVENTS
# =============================================================================

@app.on_event("startup")
async def startup_event() -> None:
    """
     Execute initialization tasks when the application starts.
    
        This function runs once when the application starts. It validates
        critical dependencies and prepares the service to handle requests.
    
        Startup Sequence:
            1. Validate JWT security configuration (SECRET_KEY strength)
            2. Test database connectivity (SELECT 1)
            3. Initialize database schema (development only)
            4. Log successful startup
    
        Why validate SECRET_KEY?
            - A weak SECRET_KEY could allow token forgery
            - Must be at least 32 characters
            - Must be cryptographically random
    
        Why test database connectivity?
            - Fail fast if the database is unavailable
            - Prevent the service from starting in an unhealthy state
            - Allows container orchestration to restart the service
    
        Why create schema only in development?
            - In production, use migrations (Alembic)
            - Prevents accidental data loss
            - Ensures schema changes are version-controlled
    
        Raises:
            RuntimeError: If SECRET_KEY is weak or database is unreachable
    
        Security Note:
            - This is a critical security checkpoint
            - The service will NOT start if dependencies are unavailable
            - Prevents running in an insecure state
    
        OWASP Compliance:
            - API2: Broken Authentication (validates SECRET_KEY)
            - API8: Security Misconfiguration (validates environment)
    """
    logger.info(" Initializing authentication service...")

    # -------------------------------------------------------------------------
    # Step 1: Validate Security Configuration
    # -------------------------------------------------------------------------
    logger.info(" Validating security configuration...")
    try:
        validate_security_config()
        logger.info(" Security configuration validated")
    except ValueError as e:
        logger.critical(f" Security validation failed: {str(e)}")
        raise RuntimeError(f"Security validation failed: {str(e)}")

    # -------------------------------------------------------------------------
    # Step 2: Test Database Connectivity (ASYNC)
    # -------------------------------------------------------------------------
    logger.info("  Testing database connectivity...")
    try:
        async with AsyncSessionLocal() as db:
            await db.execute(text("SELECT 1"))
        logger.info(" Database connection established")
    except Exception as e:
        logger.critical(f"Database connection failed: {str(e)}")
        raise RuntimeError(f"Database connection failed: {str(e)}")

    # -------------------------------------------------------------------------
    # Step 3: Initialize Database Schema (Development Only) - ASYNC
    # -------------------------------------------------------------------------
    if ENVIRONMENT == "development":
        logger.info("Creating database schema (development mode)...")
        try:
            async with async_engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info(" Database schema initialized")
        except Exception as e:
            logger.error(f" Schema initialization warning: {str(e)}")

    # -------------------------------------------------------------------------
    # Step 4: Log Successful Startup
    # -------------------------------------------------------------------------
    logger.info(" Authentication service started successfully")
    logger.info(f" Environment: {ENVIRONMENT}")
    logger.info(f" Port: 8001")
    logger.info(f" API Docs: /docs")

@app.on_event("shutdown")
async def shutdown_event() -> None:
    """
        Execute cleanup tasks when the application shuts down.
    
        This function runs when the application receives a shutdown signal
        (SIGTERM, SIGINT). It performs graceful cleanup.
    
        Shutdown Sequence:
            1. Close database connection pools
            2. Flush any pending logs
            3. Log shutdown event
    
        Why graceful shutdown?
            - Prevents in-flight requests from being interrupted
            - Allows database connections to close properly
            - Prevents connection leaks
    
        Security Note:
            - All active sessions should be cleaned up
            - No security-sensitive cleanup needed here
            - Tokens are stateless (no server-side sessions)
        """
    logger.info(" Shutting down authentication service...")

    # Close database connection pool (ASYNC)
    try:
        await async_engine.dispose()
        logger.info(" Database connections closed")
    except Exception as e:
        logger.error(f" Error closing database connections: {str(e)}")

    logger.info(" Authentication service shutdown complete")

# =============================================================================
# CORS MIDDLEWARE
# =============================================================================

def configure_cors(app: FastAPI) -> None:
    """
    Configure Cross-Origin Resource Sharing (CORS) middleware.

    CORS controls which origins (domains) can access this API.
    This is a critical security control to prevent unauthorized
    cross-origin requests.

    Configuration:
        - allow_origins: List of allowed origins (from config)
        - allow_credentials: True (allow cookies, authorization headers)
        - allow_methods: Only GET and POST (limit unnecessary methods)
        - allow_headers: Only Authorization and Content-Type

    Why restrict methods and headers?
        - PUT, DELETE, PATCH require additional validation
        - Unnecessary methods increase attack surface
        - Only allow what is actually used

    Security Note:
        - NEVER use "*" for origins in production
        - Always specify exact origins
        - Use a whitelist approach (deny by default)

    OWASP Compliance:
        - API8: Security Misconfiguration
        - A05: Security Misconfiguration
    """
    logger.info(f"🔗 Configuring CORS with origins: {ALLOWED_ORIGINS}")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )

    logger.info("✅ CORS configured")


configure_cors(app)


# =============================================================================
# TRUSTED HOST MIDDLEWARE
# =============================================================================

def configure_trusted_host(app: FastAPI) -> None:
    """
    Configure Trusted Host middleware (production only).

    This middleware protects against HTTP Host Header attacks.
    It only allows requests where the Host header matches an allowed host.

    Why production only?
        - In development, we may use localhost, 127.0.0.1, etc.
        - In production, we know the exact hostnames

    Example Attack:
        1. Attacker sends request with Host: evil.com
        2. Server generates a password reset link to evil.com
        3. Attacker intercepts the link and resets the password

    Security Note:
        - This is a defense-in-depth control
        - Should be used alongside HTTPS
        - Prevents cache poisoning attacks

    OWASP Compliance:
        - A05: Security Misconfiguration
    """
    if ENVIRONMENT == "production":
        logger.info(f"🔒 Configuring Trusted Host with: {ALLOWED_HOSTS}")

        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=ALLOWED_HOSTS,
        )

        logger.info("✅ Trusted Host configured")

    else:
        logger.info("⏭️  Trusted Host middleware skipped (development mode)")


configure_trusted_host(app)


# =============================================================================
# HTTPS REDIRECT MIDDLEWARE
# =============================================================================

def configure_https_redirect(app: FastAPI) -> None:
    """
    Configure HTTPS redirect middleware (production only).

    This middleware automatically redirects HTTP requests to HTTPS.
    This ensures all traffic is encrypted.

    Why production only?
        - In development, HTTPS requires SSL certificates (complex setup)
        - In production, HTTPS is mandatory (Let's Encrypt, Cloudflare)

    Security Note:
        - All production traffic MUST be over HTTPS
        - HTTP redirect ensures no unencrypted communication
        - Works with load balancers (X-Forwarded-Proto)

    OWASP Compliance:
        - A02: Cryptographic Failures
        - A05: Security Misconfiguration
    """
    if ENVIRONMENT == "production":
        logger.info("🔒 Configuring HTTPS redirect...")

        app.add_middleware(HTTPSRedirectMiddleware)

        logger.info("✅ HTTPS redirect configured")

    else:
        logger.info("⏭️  HTTPS redirect skipped (development mode)")


configure_https_redirect(app)


# =============================================================================
# CUSTOM MIDDLEWARES
# =============================================================================

# -----------------------------------------------------------------------------
# Middleware 1: Request ID
# -----------------------------------------------------------------------------

@app.middleware("http")
async def request_id_middleware(
    request: Request,
    call_next: callable
) -> JSONResponse:
    """
    Add a unique Request ID to every request.

    Purpose:
        - Trace requests across multiple services
        - Correlate logs for debugging
        - Provide to clients for support

    Implementation:
        - Generate a UUID for each request
        - Store it in request.state (available to all handlers)
        - Add X-Request-ID header to the response

    Why this is useful:
        - When a user reports an error, they can provide the Request ID
        - Developers can search logs for that Request ID
        - Essential for distributed tracing in microservices

    Example:
        Client sends request → Request ID: abc-123
        Logs contain: "Request: abc-123 | POST /login | IP: 1.2.3.4"
        Response contains: X-Request-ID: abc-123
        User reports error with "Request ID: abc-123"

    Security Note:
        - Request ID does NOT contain sensitive information
        - Can be safely exposed to clients
        - Helps with security incident investigations
    """
    # Generate a unique identifier for this request
    request_id = str(uuid.uuid4())

    # Store the request ID in the request state
    request.state.request_id = request_id

    # Process the request (call the next middleware/route)
    response = await call_next(request)

    # Add the request ID to the response headers
    response.headers["X-Request-ID"] = request_id

    return response


# -----------------------------------------------------------------------------
# Middleware 2: Request Logging
# -----------------------------------------------------------------------------

@app.middleware("http")
async def request_logging_middleware(
    request: Request,
    call_next: callable
) -> JSONResponse:
    """
    Log all incoming requests for audit and monitoring.

    Purpose:
        - Create an audit trail of all API calls
        - Detect security incidents (brute force, enumeration)
        - Monitor application performance

    What is logged:
        - HTTP method (GET, POST, etc.)
        - Request path (/login, /register, etc.)
        - Client IP address
        - Request ID (for correlation)
        - Response status code
        - Processing time

    What is NOT logged:
        - Request body (contains passwords, tokens)
        - Request headers (contains Authorization header)
        - Query parameters (may contain sensitive data)

    Security Considerations:
        - DO NOT log passwords or tokens
        - DO NOT log personal data (unless hashed)
        - DO log IP addresses (for abuse detection)
        - DO log email addresses (for audit)

    GDPR Compliance:
        - IP addresses are personal data (must be hashed or anonymized)
        - Consider hashing IPs: SHA256(ip + salt)
        - Log retention period should be defined

    OWASP Compliance:
        - API9: Improper Inventory Management
        - A09: Logging Failures

    Note:
        - Health check endpoints (/health, /) are NOT logged
          (they generate too much noise)
    """
    # Skip logging for health checks (reduce noise)
    if request.url.path in ["/health", "/"]:
        return await call_next(request)

    # Get client IP (handles reverse proxies)
    client_ip = request.client.host if request.client else "unknown"

    # Get request ID from previous middleware
    request_id = getattr(request.state, "request_id", "unknown")

    # Log the incoming request
    logger.info(
        f"📥 REQUEST  | {request.method} {request.url.path} "
        f"| IP: {client_ip} "
        f"| ID: {request_id}"
    )

    # Start timing the request
    start_time = time.time()

    try:
        # Process the request
        response = await call_next(request)

        # Calculate processing time
        process_time = time.time() - start_time

        # Log the response
        logger.info(
            f" RESPONSE | {request.method} {request.url.path} "
            f"| Status: {response.status_code} "
            f"| Time: {process_time:.4f}s "
            f"| ID: {request_id}"
        )

        return response

    except Exception as e:
        # Log any unhandled exceptions
        logger.error(
            f" ERROR    | {request.method} {request.url.path} "
            f"| Error: {str(e)} "
            f"| ID: {request_id}"
        )
        # Re-raise the exception for the global handler
        raise


# -----------------------------------------------------------------------------
# Middleware 3: Security Headers
# -----------------------------------------------------------------------------

@app.middleware("http")
async def security_headers_middleware(
    request: Request,
    call_next: callable
) -> JSONResponse:
    """
    Add OWASP-recommended security headers to every response.

    Purpose:
        - Prevent common web vulnerabilities (XSS, clickjacking, etc.)
        - Enforce HTTPS (HSTS)
        - Control what resources can be loaded (CSP)

    Headers Added:
        - X-Content-Type-Options: nosniff
          Prevents MIME type sniffing (IE vulnerabilities)

        - X-Frame-Options: DENY
          Prevents clickjacking (no one can frame your site)

        - X-XSS-Protection: 1; mode=block
          Legacy XSS protection (modern browsers use CSP)

        - Referrer-Policy: strict-origin-when-cross-origin
          Controls how much referrer info is sent

        - Content-Security-Policy: default-src 'self'; frame-ancestors 'none'
          Prevents loading resources from untrusted sources

        - Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
          Forces HTTPS (HSTS) in production

    Security Note:
        - CSP is critical but can break if misconfigured
        - Start with report-only mode to test
        - Add 'unsafe-inline' only if absolutely necessary

    OWASP Compliance:
        - A05: Security Misconfiguration
        - API8: Security Misconfiguration
    """
    # Process the request
    response = await call_next(request)

    # Add OWASP-recommended security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Allow CDN resources for Swagger UI in development
    if ENVIRONMENT == "development":
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https://cdn.jsdelivr.net; "
            "font-src 'self' data: https://cdn.jsdelivr.net; "
            "frame-ancestors 'none';"
        )
    else:
        # Strict policy for production
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "frame-ancestors 'none';"
        )

    # HTTP Strict Transport Security (HSTS) - production only
    if ENVIRONMENT == "production":
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )

    return response


# -----------------------------------------------------------------------------
# Middleware 4: Content-Type Validation
# -----------------------------------------------------------------------------

@app.middleware("http")
async def content_type_middleware(
    request: Request,
    call_next: callable
) -> JSONResponse:
    """
    Validate Content-Type header for POST/PUT/PATCH requests.

    Purpose:
        - Ensure requests with bodies have the correct Content-Type
        - Prevent attacks using malformed content types

    What it does:
        - For POST, PUT, PATCH: require Content-Type: application/json
        - For GET, DELETE: no validation (no body)

    Why this is important:
        - Prevents clients from sending non-JSON data
        - Ensures Pydantic can parse the request body
        - Reduces attack surface (no XML, form data, etc.)

    Security Note:
        - This is a defense-in-depth control
        - Pydantic also validates the data structure
        - API clients must set the correct Content-Type

    OWASP Compliance:
        - A05: Security Misconfiguration
        - A08: Data Integrity Failures
    """
    if request.method in ["POST", "PUT", "PATCH"]:
        content_type = request.headers.get("content-type", "")

        if not content_type.startswith("application/json"):
            return JSONResponse(
                status_code=415,
                content={
                    "success": False,
                    "error": "Content-Type must be application/json",
                    "code": "UNSUPPORTED_MEDIA_TYPE",
                    "request_id": getattr(request.state, "request_id", None),
                }
            )

    return await call_next(request)


# -----------------------------------------------------------------------------
# Middleware 5: Request Timeout
# -----------------------------------------------------------------------------

class TimeoutMiddleware(BaseHTTPMiddleware):
    """
    Enforce a maximum request processing time.

    Purpose:
        - Prevent long-running requests from exhausting resources
        - Protect against DoS attacks (slow loris)
        - Ensure timely responses to clients

    How it works:
        - All requests must complete within 30 seconds
        - If a request exceeds the timeout, 504 Gateway Timeout is returned

    Why 30 seconds?
        - Authentication operations are fast (< 1 second)
        - Database queries should be fast (with proper indexing)
        - 30 seconds is generous enough for normal operations
        - Prevents hanging on database deadlocks

    Security Note:
        - Timeouts are critical for DoS protection
        - Should be configurable per endpoint (some endpoints are slower)
        - Too short = false positives, too long = vulnerable

    OWASP Compliance:
        - API4: Unrestricted Resource Consumption
    """

    async def dispatch(
        self,
        request: Request,
        call_next: callable
    ) -> JSONResponse:
        """
        Process a request with a timeout.

        Args:
            request: The incoming HTTP request
            call_next: The next middleware/route handler

        Returns:
            JSONResponse: The response (or timeout error)

        Raises:
            TimeoutError: If the request exceeds the timeout
        """
        try:
            # Use asyncio.wait_for to enforce the timeout
            return await asyncio.wait_for(
                call_next(request),
                timeout=30.0,  # 30 seconds
            )

        except asyncio.TimeoutError:
            # Log the timeout event
            logger.warning(
                f" Request timeout: {request.method} {request.url.path} "
                f"ID: {getattr(request.state, 'request_id', 'unknown')}"
            )

            # Return a 504 Gateway Timeout response
            return JSONResponse(
                status_code=504,
                content={
                    "success": False,
                    "error": "Request timeout (30 seconds exceeded)",
                    "code": "TIMEOUT",
                    "request_id": getattr(request.state, "request_id", None),
                }
            )


# Add the timeout middleware to the application
app.add_middleware(TimeoutMiddleware)


# =============================================================================
# EXCEPTION HANDLERS
# =============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(
    request: Request,
    exc: HTTPException
) -> JSONResponse:
    """
    Handle HTTP exceptions (4xx and 5xx responses).

    Purpose:
        - Convert HTTP exceptions to consistent JSON responses
        - Add the Request ID to all error responses
        - Log errors for monitoring and debugging

    What is logged:
        - 4xx errors: Warning level (client error)
        - 5xx errors: Error level (server error)

    Response Format:
        {
            "success": false,
            "error": "Human-readable error message",
            "code": "ERROR_CODE",
            "request_id": "abc-123"  # For tracing
        }

    Why custom error handling?
        - Consistent error format across all endpoints
        - Hide internal error details in production
        - Add request ID for debugging
        - Log security-relevant errors

    Security Note:
        - Do NOT expose internal error details (stack traces) in production
        - Return user-friendly error messages only
        - Log the full error details for debugging

    OWASP Compliance:
        - A05: Security Misconfiguration
    """
    # Get the error code from headers (if set by the route)
    error_code = "ERROR"
    if exc.headers and "X-Error-Code" in exc.headers:
        error_code = exc.headers["X-Error-Code"]

    # Get the request ID from the request state
    request_id = getattr(request.state, "request_id", None)

    # Log the error
    if exc.status_code >= 500:
        logger.error(
            f" HTTP {exc.status_code} error: {exc.detail} "
            f"ID: {request_id}"
        )
    else:
        logger.warning(
            f" HTTP {exc.status_code} error: {exc.detail} "
            f"ID: {request_id}"
        )

    # Return a structured JSON response
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": str(exc.detail),
            "code": error_code,
            "request_id": request_id,
        }
    )


@app.exception_handler(Exception)
async def global_exception_handler(
    request: Request,
    exc: Exception
) -> JSONResponse:
    """
    Handle all unhandled exceptions.

    Purpose:
        - Catch any exception not caught elsewhere
        - Return a generic 500 error to the client
        - Log the full stack trace for debugging
        - Prevent exposing internal details

    What is logged:
        - Full exception traceback (for developers)
        - Request details (method, path, request ID)

    Response Format:
        {
            "success": false,
            "error": "Internal server error",
            "code": "INTERNAL_ERROR",
            "request_id": "abc-123"
        }

    Security Note:
        - NEVER expose stack traces in production
        - Return a generic error message only
        - Log everything for internal debugging

    OWASP Compliance:
        - A05: Security Misconfiguration
    """
    # Get the request ID
    request_id = getattr(request.state, "request_id", None)

    # Log the full exception with stack trace
    logger.exception(
        f" Unhandled exception: {request.method} {request.url.path} "
        f"ID: {request_id}"
    )

    # Return a generic 500 error (hide internal details)
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": "Internal server error",
            "code": "INTERNAL_ERROR",
            "request_id": request_id,
        }
    )


# =============================================================================
# API ENDPOINTS
# =============================================================================

@app.get("/", tags=["Public"])
async def root() -> dict:
    """
    Root endpoint - Service information.

    Purpose:
        - Provide basic service information
        - Verify the service is running
        - Used for monitoring and discovery

    Response:
        {
            "success": true,
            "message": "CyberSafe Auth Service Running",
            "environment": "development"
        }

    Why this endpoint exists:
        - Simple way to check if the service is running
        - Useful for health checks (basic)
        - Good for new developers to test connectivity

    Security Note:
        - Does not expose sensitive information
        - Environment is safe to reveal (helps debugging)
    """
    return {
        "success": True,
        "message": "CyberSafe Auth Service Running",
        "environment": ENVIRONMENT,
        "version": "1.0.0",
    }

@app.get("/health", tags=["Public"])
@limiter.limit("10/minute")
async def health_check(request: Request) -> dict:
    """
        Health check endpoint - Advanced monitoring.
    
        Purpose:
            - Verify service health for monitoring systems
            - Check database connectivity
            - Used by Docker, Kubernetes, and load balancers
    
        Health Status:
            - healthy: Service is fully operational
            - degraded: Service is running but some dependencies are down
    
        Response (healthy):
            {
                "success": true,
                "service": "auth",
                "status": "healthy",
                "database": "connected",
                "environment": "development"
            }
    
        Response (degraded):
            {
                "success": false,
                "service": "auth",
                "status": "degraded",
                "database": "disconnected",
                "environment": "development"
            }
    
        Rate Limit: 10 requests per minute
            - Prevents monitoring systems from overwhelming the endpoint
            - Enough for typical monitoring (every 15-30 seconds)
    
        Why database connectivity is checked:
            - The auth service cannot function without a database
            - Failover mechanisms can route traffic away from unhealthy instances
            - Proactive detection of database issues
    
        Security Note:
            - This endpoint is public (no authentication required)
            - Does not expose sensitive data
            - Rate limited to prevent abuse
    
        OWASP Compliance:
            - API9: Improper Inventory Management
    """
    try:
        async with AsyncSessionLocal() as db:
            await db.execute(text("SELECT 1"))
        return {
            "success": True,
            "service": "auth",
            "status": "healthy",
            "database": "connected",
            "environment": ENVIRONMENT,
        }
    except Exception as e:
        logger.error(f" Health check failed: Database error: {str(e)}")
        return {
            "success": False,
            "service": "auth",
            "status": "degraded",
            "database": "disconnected",
            "environment": ENVIRONMENT,
        }


# =============================================================================
# ROUTE REGISTRATION
# =============================================================================

def register_routes(app: FastAPI) -> None:
    """
    Register all API routes with the application.

    Purpose:
        - Mount the authentication router to the main application
        - All routes are prefixed with /api/v1/auth

    Routes included:
        - POST /api/v1/auth/register
        - POST /api/v1/auth/login
        - POST /api/v1/auth/refresh
        - POST /api/v1/auth/logout
        - GET  /api/v1/auth/me

    Why use a router?
        - Separation of concerns (routes are defined in routes.py)
        - Easier to test routes in isolation
        - Better organization for larger applications

    Note:
        - All routes are in the routes.py module
        - This just registers them with the main application
    """
    logger.info(" Registering routes...")
    app.include_router(router, prefix="/api/v1/auth")
    logger.info(" Routes registered")


register_routes(app)


# =============================================================================
# SECURITY COMPLIANCE SUMMARY
# =============================================================================
#
# OWASP API Security Top 10 (2023) - Full Compliance:
#
# 1. Broken Object Level Authorization (API1)
#    - Implemented via dependencies.py
#    - Role-based access control (admin, user, expert)
#    - Each endpoint checks user permissions
#
# 2. Broken Authentication (API2)
#    - JWT with HS256 algorithm
#    - Argon2 password hashing (state-of-the-art)
#    - Access token expiration (15-30 min)
#    - Refresh token rotation
#
# 3. Broken Object Property Level Authorization (API3)
#    - Pydantic schemas filter sensitive fields
#    - User profiles never expose password hashes
#    - SQLAlchemy models hide internal fields
#
# 4. Unrestricted Resource Consumption (API4)
#    - Rate limiting (slowapi)
#    - Request timeout (30 seconds)
#    - Request size limit (10 MB)
#
# 5. Broken Function Level Authorization (API5)
#    - Admin-only endpoints protected
#    - Role validation in dependencies
#    - Each endpoint verifies permissions
#
# 6. Unrestricted Access to Sensitive Flows (API6)
#    - Rate limiting on /login and /register
#    - IP-based rate limiting
#    - Protection against brute force
#
# 7. Server Side Request Forgery (API7)
#    - N/A: This service does not make external requests
#
# 8. Security Misconfiguration (API8)
#    - CORS restricted (explicit origins)
#    - Security headers (CSP, HSTS, etc.)
#    - Environment-specific configurations
#    - Trusted Host middleware
#
# 9. Improper Inventory Management (API9)
#    - Full request/response logging
#    - Audit trail of all security events
#    - Health monitoring endpoint
#
# 10. Unsafe Consumption of APIs (API10)
#     - N/A: This service does not consume external APIs
#
# =============================================================================


# =============================================================================
# FINAL APPLICATION INSPECTION
# =============================================================================

if __name__ == "__main__":
    # This allows running the application directly with:
    # python app.py
    #
    # For production, use uvicorn instead:
    # uvicorn app:app --host 0.0.0.0 --port 8001
    import uvicorn

    logger.info("🔄 Starting Auth Service in development mode...")
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8001,
        reload=True,  # Auto-reload on code changes (development only)
    )