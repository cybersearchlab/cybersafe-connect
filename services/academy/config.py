"""
services/academy/config.py
================================================================================
CyberSafe Connect Academy Microservice
================================================================================

Application configuration.

Loads environment variables and validates critical settings.

Responsibilities:
    • Database configuration
    • JWT configuration
    • Media storage configuration
    • File upload limits
    • Environment settings

This file MUST NOT contain business logic.

================================================================================
"""

import os

from dotenv import load_dotenv

load_dotenv()


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./data/academy.db"
)


JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")

if not JWT_SECRET_KEY:
    raise RuntimeError(
        "JWT_SECRET_KEY environment variable is required."
    )

if len(JWT_SECRET_KEY) < 64:
    raise RuntimeError(
        "JWT_SECRET_KEY is too short. Minimum 64 characters required."
    )


JWT_ALGORITHM = os.getenv(
    "JWT_ALGORITHM",
    "HS256"
)


MEDIA_ROOT = os.path.abspath(
    os.getenv(
        "MEDIA_ROOT",
        "./media"
    )
)

MEDIA_URL = os.getenv(
    "MEDIA_URL",
    "/media"
)


ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "ALLOWED_ORIGINS",
        "http://localhost:3000,http://localhost:3001"
    ).split(",")
    if origin.strip()
]


ENVIRONMENT = os.getenv(
    "ENVIRONMENT",
    "development"
)

VALID_ENVIRONMENTS = [
    "development",
    "testing",
    "production"
]

if ENVIRONMENT not in VALID_ENVIRONMENTS:
    raise RuntimeError(
        "ENVIRONMENT must be development, testing or production."
    )


PORT = int(
    os.getenv(
        "PORT",
        "8006"
    )
)

if PORT < 1 or PORT > 65535:
    raise RuntimeError(
        "PORT must be between 1 and 65535."
    )


MAX_IMAGE_SIZE_MB = int(
    os.getenv(
        "MAX_IMAGE_SIZE_MB",
        "5"
    )
)

MAX_VIDEO_SIZE_MB = int(
    os.getenv(
        "MAX_VIDEO_SIZE_MB",
        "100"
    )
)

MAX_PDF_SIZE_MB = int(
    os.getenv(
        "MAX_PDF_SIZE_MB",
        "20"
    )
)


if MAX_IMAGE_SIZE_MB <= 0:
    raise RuntimeError(
        "MAX_IMAGE_SIZE_MB must be positive."
    )


if MAX_VIDEO_SIZE_MB <= 0:
    raise RuntimeError(
        "MAX_VIDEO_SIZE_MB must be positive."
    )


if MAX_PDF_SIZE_MB <= 0:
    raise RuntimeError(
        "MAX_PDF_SIZE_MB must be positive."
    )