"""
services/academy/storage.py
================================================================================
CyberSafe Connect Academy Microservice
================================================================================

File storage management.

Responsibilities:
    • File upload validation
    • File size validation
    • File extension validation
    • Media file persistence
    • Media URL generation
    • Media directories initialization

This file MUST NOT contain:
    • Business logic
    • API routes
    • Authentication logic
    • Database operations

================================================================================
"""

import logging
import uuid
from pathlib import Path

from fastapi import UploadFile

from config import (
    MAX_IMAGE_SIZE_MB,
    MAX_PDF_SIZE_MB,
    MAX_VIDEO_SIZE_MB,
    MEDIA_ROOT,
    MEDIA_URL,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Allowed file extensions
# =============================================================================

ALLOWED_IMAGE_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".webp",
    ".gif",
}

ALLOWED_VIDEO_EXTENSIONS = {
    ".mp4",
    ".webm",
    ".mov",
    ".avi",
}

ALLOWED_PDF_EXTENSIONS = {
    ".pdf",
}


# =============================================================================
# Storage directories
# =============================================================================

MODULE_IMAGE_DIR = "academy/modules"
QUESTION_IMAGE_DIR = "academy/questions"
VIDEO_DIR = "academy/videos"
PDF_DIR = "academy/pdfs"


# =============================================================================
# Validation helpers
# =============================================================================

def _validate_extension(
    filename: str,
    allowed_extensions: set[str],
) -> str:
    """
    Validate uploaded file extension.
    """

    extension = Path(filename).suffix.lower()

    if extension not in allowed_extensions:
        raise ValueError(
            f"Unsupported file format. "
            f"Allowed: {', '.join(sorted(allowed_extensions))}"
        )

    return extension


def _validate_size(
    file_size: int,
    max_mb: int,
) -> None:
    """
    Validate file size.
    """

    max_bytes = max_mb * 1024 * 1024

    if file_size > max_bytes:
        raise ValueError(
            f"File too large. Maximum allowed size is {max_mb} MB."
        )


# =============================================================================
# File saving logic
# =============================================================================

async def save_upload(
    file: UploadFile,
    subdirectory: str,
    allowed_extensions: set[str],
    max_mb: int,
) -> str:
    """
    Save uploaded file securely.
    """

    extension = _validate_extension(
        file.filename or "file",
        allowed_extensions,
    )

    target_directory = Path(MEDIA_ROOT) / subdirectory

    target_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    generated_filename = (
        f"{uuid.uuid4().hex}{extension}"
    )

    destination = (
        target_directory / generated_filename
    )

    content = await file.read()

    _validate_size(
        len(content),
        max_mb,
    )

    try:

        destination.write_bytes(content)

        logger.info(
            "File stored successfully: %s",
            destination,
        )

    except OSError as exc:

        logger.error(
            "File storage failed: %s",
            exc,
        )

        raise ValueError(
            "Failed to store uploaded file."
        ) from exc

    return str(
        Path(subdirectory) / generated_filename
    ).replace("\\", "/")


# =============================================================================
# Specialized upload functions
# =============================================================================

async def save_image(
    file: UploadFile,
) -> str:
    """
    Save module cover image.
    """

    return await save_upload(
        file=file,
        subdirectory=MODULE_IMAGE_DIR,
        allowed_extensions=ALLOWED_IMAGE_EXTENSIONS,
        max_mb=MAX_IMAGE_SIZE_MB,
    )


async def save_question_image(
    file: UploadFile,
) -> str:
    """
    Save question illustration image.
    """

    return await save_upload(
        file=file,
        subdirectory=QUESTION_IMAGE_DIR,
        allowed_extensions=ALLOWED_IMAGE_EXTENSIONS,
        max_mb=MAX_IMAGE_SIZE_MB,
    )


async def save_video(
    file: UploadFile,
) -> str:
    """
    Save uploaded video.
    """

    return await save_upload(
        file=file,
        subdirectory=VIDEO_DIR,
        allowed_extensions=ALLOWED_VIDEO_EXTENSIONS,
        max_mb=MAX_VIDEO_SIZE_MB,
    )


async def save_pdf(
    file: UploadFile,
) -> str:
    """
    Save uploaded PDF document.
    """

    return await save_upload(
        file=file,
        subdirectory=PDF_DIR,
        allowed_extensions=ALLOWED_PDF_EXTENSIONS,
        max_mb=MAX_PDF_SIZE_MB,
    )


# =============================================================================
# Media utilities
# =============================================================================

def media_url(
    path: str | None,
) -> str | None:
    """
    Generate public media URL.
    """

    if not path:
        return None

    return (
        f"{MEDIA_URL.rstrip('/')}/{path}"
    )


def ensure_media_dirs() -> None:
    """
    Create media directories on startup.
    """

    directories = [
        MODULE_IMAGE_DIR,
        QUESTION_IMAGE_DIR,
        VIDEO_DIR,
        PDF_DIR,
    ]

    for directory in directories:

        Path(
            MEDIA_ROOT,
            directory,
        ).mkdir(
            parents=True,
            exist_ok=True,
        )

    logger.info(
        "Media directories initialized successfully."
    )