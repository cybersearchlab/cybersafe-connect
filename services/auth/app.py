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
    • Route registration
    • Health monitoring
    • Startup initialization

This file MUST NOT contain business logic.

Business logic belongs to:

    • routes.py
    • services.py

Security logic belongs to:

    • security.py

================================================================================
"""

import sys
import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from config import ALLOWED_ORIGINS
from database import Base, engine, SessionLocal
from routes import router


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    stream=sys.stdout
)

logger = logging.getLogger(__name__)


app = FastAPI(
    title="CyberSafe Connect - Auth Service",
    version="1.0.0"
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