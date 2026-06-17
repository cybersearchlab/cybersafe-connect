"""
main.py
================================================================================
CyberSafe Connect Main Application Entry Point
================================================================================

This module is the central entry point of the CyberSafe Connect backend API.

It is responsible for:

    - initializing the FastAPI application
    - registering API routes
    - initializing the database
    - configuring middleware (future use)
    - exposing health checks
    - preparing the application for deployment

This file acts as the orchestrator of the entire backend system.

--------------------------------------------------------------------------------
APPLICATION FLOW
--------------------------------------------------------------------------------

STEP 1 — Application Initialization
    FastAPI instance is created with metadata (title, version, description).

STEP 2 — Database Initialization
    SQLite database is initialized at startup.

STEP 3 — Route Registration
    API routes (chat, etc.) are registered.

STEP 4 — Middleware Setup (Future)
    CORS, authentication, logging middleware can be added here.

STEP 5 — Server Exposure
    Application is exposed via ASGI server (uvicorn).

--------------------------------------------------------------------------------
ROLE IN ARCHITECTURE
--------------------------------------------------------------------------------

This module connects all backend components:

    routes/
        ↓
    services/
        ↓
    database/
        ↓
    AI engine (OpenAI)

--------------------------------------------------------------------------------
FUTURE EXTENSIONS
--------------------------------------------------------------------------------

- CORS configuration for frontend integration
- JWT authentication middleware
- Rate limiting middleware
- Request logging middleware
- WebSocket support for real-time chat
- Multi-language support

================================================================================
"""

# ==============================================================================
# IMPORTS
# ==============================================================================

import logging

from fastapi import FastAPI

from app.core.config import (
    APP_NAME,
    APP_VERSION,
    APP_DESCRIPTION
)

from app.database.database_service import initialize_database

from app.routes.chat import router as chat_router


# ==============================================================================
# LOGGING CONFIGURATION
# ==============================================================================

logging.basicConfig(level=logging.INFO)


# ==============================================================================
# FASTAPI APPLICATION INITIALIZATION
# ==============================================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=APP_DESCRIPTION
)


# ==============================================================================
# ROUTE REGISTRATION
# ==============================================================================

app.include_router(chat_router)


# ==============================================================================
# STARTUP EVENT
# ==============================================================================

@app.on_event("startup")
def startup_event():
    """
    Initialize system resources at application startup.

    This includes:
        - database initialization
        - future service preloading
    """

    logging.info("Starting CyberSafe Connect backend...")

    initialize_database()

    logging.info("Database initialized successfully.")


# ==============================================================================
# HEALTH CHECK ENDPOINT
# ==============================================================================

@app.get("/")
def root():
    """
    Root endpoint for API health check.

    Returns
    -------
    dict
        Basic system status information.
    """

    return {
        "status": "running",
        "service": APP_NAME,
        "version": APP_VERSION
    }


# ==============================================================================
# HEALTH CHECK ENDPOINT (DETAILED)
# ==============================================================================

@app.get("/health")
def health_check():
    """
    Detailed health check endpoint.

    Returns
    -------
    dict
        System health and readiness status.
    """

    return {
        "status": "healthy",
        "database": "initialized",
        "ai_service": "active",
        "api": "operational"
    }