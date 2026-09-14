"""
services/auth/app.py
================================================================================
CyberSafe Connect Authentication Microservice
================================================================================

Entry point of the authentication service.

Responsibilities:

    • FastAPI application bootstrap
    • Middleware registration
    • Global exception handling
    • Rate limiting registration (slowapi)
    • Route registration
    • Health monitoring
    • Startup initialization

This file MUST NOT contain business logic.

Business logic belongs to:

    • routes.py
    • services.py

Security logic belongs to:

    • security.py

Rate limiting logic belongs to:

    • limiter.py

================================================================================
"""

# 1. Standard library
import sys
import logging

# 2. Third-party
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded
from sqlalchemy import text

# 3. Local — lowest level first
from config import ALLOWED_ORIGINS, ENVIRONMENT
from database import Base, engine, SessionLocal
from limiter import limiter
from routes import router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    stream=sys.stdout
)

logger = logging.getLogger(__name__)

class SecurityHeadersMiddleware:
    """
    Pure ASGI middleware (not BaseHTTPMiddleware).

    Why pure ASGI:
        Starlette's BaseHTTPMiddleware runs *before* Uvicorn adds its own
        'Server' header, so attempting to delete or replace it there has no
        effect — Uvicorn re-adds it afterwards, producing 'uvicorn,CyberSafe'.
        A pure ASGI middleware wraps the 'send' callable and rewrites the
        headers list *after* Starlette has finished, but *before* Uvicorn
        commits them to the wire.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = message.get("headers", [])

                # Drop any existing Server header (case-insensitive)
                headers = [
                    (k, v) for (k, v) in headers
                    if k.lower() != b"server"
                ]

                # Standard security headers (OWASP Secure Headers Project)
                headers.append((b"server", b"CyberSafe"))
                headers.append((b"x-content-type-options", b"nosniff"))
                headers.append((b"x-frame-options", b"DENY"))
                headers.append((b"referrer-policy", b"strict-origin-when-cross-origin"))
                headers.append((
                    b"content-security-policy",
                    b"default-src 'self'; frame-ancestors 'none'"
                ))
                headers.append((b"permissions-policy", b"geolocation=(), microphone=(), camera=()"))

                # HSTS only makes sense over HTTPS; enable in staging/production
                if ENVIRONMENT in ("staging", "production"):
                    headers.append((
                        b"strict-transport-security",
                        b"max-age=31536000; includeSubDomains"
                    ))

                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)

# In production, disable the interactive documentation and the OpenAPI
# schema, to avoid exposing the full API surface to unauthenticated users.
app = FastAPI(
    title="CyberSafe Connect - Auth Service",
    version="1.0.0",
    docs_url="/docs" if ENVIRONMENT != "production" else None,
    redoc_url="/redoc" if ENVIRONMENT != "production" else None,
    openapi_url="/openapi.json" if ENVIRONMENT != "production" else None,
)

# Register the rate limiter on the application state, and add a custom
# exception handler that returns the project's standard error envelope
# ({success, error, code}) instead of slowapi's default plain-text response.
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={
            "success": False,
            "error": "Too many requests. Please try again later.",
            "code": "RATE_LIMITED"
        }
    )


@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
    logger.info("Authentication service started")


app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,

    allow_methods=[
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "OPTIONS"
    ],

    allow_headers=[
        "Authorization",
        "Content-Type"
    ]
)

# Add AFTER CORS so it runs FIRST on the response path (wraps the CORS response)
app.add_middleware(SecurityHeadersMiddleware)

@app.exception_handler(HTTPException)
async def http_exception_handler(
    request: Request,
    exc: HTTPException
):

    code = "ERROR"

    if exc.headers and "X-Error-Code" in exc.headers:
        code = exc.headers["X-Error-Code"]

    detail = exc.detail

    if isinstance(detail, dict):
        message = detail.get("message", "Unknown error")
    else:
        message = str(detail)

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": message,
            "code": code
        }
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError
):
    # In development, return detailed validation errors to ease debugging.
    # In production, return a generic message to avoid leaking schema details.
    if ENVIRONMENT == "production":
        return JSONResponse(
            status_code=422,
            content={
                "success": False,
                "error": "Invalid request payload.",
                "code": "VALIDATION_ERROR"
            }
        )

    return JSONResponse(
        status_code=422,
        content={
            "success": False,
            "error": "Invalid request payload.",
            "code": "VALIDATION_ERROR",
            "details": exc.errors()
        }
    )


@app.get("/")
def root():

    return {
        "success": True,
        "message": "CyberSafe Auth Service Running"
    }


@app.get("/health")
def health():

    db = SessionLocal()

    try:
        db.execute(text("SELECT 1"))

        return {
            "success": True,
            "service": "auth",
            "status": "healthy",
            "database": "connected"
        }

    except Exception:

        return {
            "success": False,
            "service": "auth",
            "status": "degraded",
            "database": "disconnected"
        }

    finally:
        db.close()


app.include_router(router)