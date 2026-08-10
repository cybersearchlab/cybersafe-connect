"""
services/academy/app.py
================================================================================
CyberSafe Connect Academy Microservice
================================================================================

Main FastAPI application entry point.

Responsibilities:
    • FastAPI application initialization
    • Middleware registration
    • Route registration
    • Global exception handling
    • Database initialization
    • Health monitoring
    • Static media serving

This file MUST NOT contain:
    • Business logic
    • Authentication logic
    • Database queries

Business logic belongs to:
    • services.py

Authentication logic belongs to:
    • security.py
    • dependencies.py

================================================================================
"""

import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from config import (
    ALLOWED_ORIGINS,
    ENVIRONMENT,
    MEDIA_ROOT,
    MEDIA_URL,
)
from database import Base, SessionLocal, engine
from routes import router
from storage import ensure_media_dirs


# =============================================================================
# Logging Configuration
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    stream=sys.stdout,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Application Lifespan
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Handle startup and shutdown lifecycle events.
    """

    logger.info("Initializing Academy service...")

    ensure_media_dirs()

    # Development only.
    # Production should use Alembic migrations.
    if ENVIRONMENT == "development":
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables initialized")

    logger.info("Academy service started successfully")

    yield

    logger.info("Academy service shutdown complete")


# =============================================================================
# FastAPI Application
# =============================================================================

app = FastAPI(
    title="CyberSafe Connect Academy Service",
    description="Cybersecurity learning platform microservice",
    version="1.0.0",
    lifespan=lifespan,
)


# =============================================================================
# Middleware Configuration
# =============================================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# Static Media Configuration
# =============================================================================

# Must exist before StaticFiles mount
ensure_media_dirs()

app.mount(
    MEDIA_URL,
    StaticFiles(directory=MEDIA_ROOT),
    name="media",
)


# =============================================================================
# Exception Handlers
# =============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(
    _: Request,
    exc: HTTPException,
):
    """
    Handle expected HTTP exceptions.
    """

    error_code = "ERROR"

    if exc.headers and "X-Error-Code" in exc.headers:
        error_code = exc.headers["X-Error-Code"]

    detail = exc.detail

    message = (
        detail.get("message", str(detail))
        if isinstance(detail, dict)
        else str(detail)
    )

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": message,
            "code": error_code,
        },
    )


@app.exception_handler(Exception)
async def global_exception_handler(
    _: Request,
    exc: Exception,
):
    """
    Handle unexpected server errors.
    """

    logger.exception(
        "Unhandled exception occurred: %s",
        exc,
    )

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "success": False,
            "error": "Internal server error",
            "code": "INTERNAL_SERVER_ERROR",
        },
    )


# =============================================================================
# System Routes
# =============================================================================

@app.get("/")
def root():
    """
    Root endpoint.
    """

    return {
        "success": True,
        "message": "CyberSafe Academy Service Running",
    }


@app.get("/health")
def health_check():
    """
    Database health check endpoint.
    """

    db = SessionLocal()

    try:
        db.execute(text("SELECT 1"))

        return {
            "success": True,
            "service": "academy",
            "status": "healthy",
            "database": "connected",
        }

    except Exception as exc:

        logger.error(
            "Database health check failed: %s",
            exc,
        )

        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "success": False,
                "service": "academy",
                "status": "degraded",
                "database": "disconnected",
            },
        )

    finally:
        db.close()


# =============================================================================
# API Routes
# =============================================================================

app.include_router(router)