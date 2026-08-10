"""
services/academy/routes.py
===============================================================================
CyberSafe Connect Academy Service API Routes
===============================================================================

This module defines all HTTP endpoints exposed by the Academy microservice.

Responsibilities
----------------

This layer is strictly responsible for:

    • HTTP request parsing
    • Dependency injection
    • JWT-based authentication enforcement
    • Role-based access control enforcement
    • Request payload validation
    • File upload handling
    • Delegation to business logic layer

This module MUST NOT contain:

    • Business logic
    • Database business rules
    • JWT verification logic
    • Persistent storage logic

Architecture Boundaries
-----------------------

Business logic:
    • services.py

Authentication:
    • dependencies.py
    • security.py

Storage handling:
    • storage.py

Security Principles
-------------------

• Zero-trust architecture
• JWT authentication delegated to auth service
• Academy never accesses auth database
• Role-based authorization enforced per endpoint
• Administrative routes protected
• Uploaded files validated before persistence
• Invalid payloads rejected early

===============================================================================
"""

import json
import logging

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    UploadFile,
    status,
)

from sqlalchemy.orm import Session

from dependencies import (
    AuthUser,
    get_current_user,
    get_db,
    get_optional_user,
    require_admin,
)

from enums import TargetRole

from schemas import (
    ModuleCreateRequest,
    QuizSubmitRequest,
)

from services import (
    create_module,
    get_module_detail,
    get_progress,
    list_modules,
    submit_quiz,
)

from storage import (
    save_image,
    save_pdf,
    save_video,
)

logger = logging.getLogger(__name__)

MAX_QUIZ_JSON_SIZE = 100_000


router = APIRouter(
    prefix="/academy",
    tags=["Academy"],
)


# =============================================================================
# PUBLIC ENDPOINTS
# =============================================================================

@router.get(
    "/modules",
    status_code=status.HTTP_200_OK,
)
def module_list(
    db: Session = Depends(get_db),
    user: AuthUser | None = Depends(get_optional_user),
):
    """
    Retrieve all modules accessible to current user.

    Access rules:

        • Anonymous users → citizen modules only
        • Company users → company modules
        • Admin users → unrestricted access
    """

    return list_modules(db, user)


@router.get(
    "/modules/{module_id}",
    status_code=status.HTTP_200_OK,
)
def module_detail(
    module_id: int,
    db: Session = Depends(get_db),
    user: AuthUser | None = Depends(get_optional_user),
):
    """
    Retrieve detailed academy module.

    Security:

        Access permissions validated
        against module target role.
    """

    return get_module_detail(
        db,
        module_id,
        user
    )


# =============================================================================
# AUTHENTICATED ENDPOINTS
# =============================================================================

@router.post(
    "/quiz/submit",
    status_code=status.HTTP_200_OK,
)
def quiz_submit(
    payload: QuizSubmitRequest,
    db: Session = Depends(get_db),
    user: AuthUser = Depends(get_current_user),
):
    """
    Submit module quiz answers.

    Authentication required.
    """

    return submit_quiz(
        db,
        user,
        payload
    )


@router.get(
    "/progress",
    status_code=status.HTTP_200_OK,
)
def progress(
    db: Session = Depends(get_db),
    user: AuthUser = Depends(get_current_user),
):
    """
    Retrieve authenticated user academy progress.
    """

    return get_progress(
        db,
        user
    )


# =============================================================================
# ADMINISTRATIVE ENDPOINTS
# =============================================================================

@router.post(
    "/admin/modules",
    status_code=status.HTTP_201_CREATED,
)
async def admin_create_module(
    title: str = Form(...),
    description: str = Form(...),
    content: str = Form(...),
    target_roles: TargetRole = Form(TargetRole.citizen),
    display_order: int = Form(0),
    video_url: str | None = Form(None),
    questions_json: str = Form("[]"),
    image: UploadFile | None = File(None),
    video_file: UploadFile | None = File(None),
    pdf_file: UploadFile | None = File(None),
    db: Session = Depends(get_db),
    admin: AuthUser = Depends(require_admin),
):
    """
    Create academy learning module.

    Restricted to administrators.

    Supports:

        • Cover image upload
        • Video upload
        • PDF upload
        • Quiz creation
    """

    logger.info(
        "Module creation requested by admin=%s",
        admin.id
    )

    if len(questions_json) > MAX_QUIZ_JSON_SIZE:
        raise HTTPException(
            status_code=400,
            detail="Quiz payload too large",
            headers={
                "X-Error-Code": "PAYLOAD_TOO_LARGE"
            },
        )

    try:

        questions_data = json.loads(
            questions_json
        )

        payload = ModuleCreateRequest(
            title=title,
            description=description,
            content=content,
            video_url=video_url,
            target_roles=target_roles,
            display_order=display_order,
            questions=questions_data,
        )

    except (json.JSONDecodeError, ValueError) as exc:

        logger.warning(
            "Invalid module payload: %s",
            str(exc)
        )

        raise HTTPException(
            status_code=400,
            detail=f"Invalid module data: {exc}",
            headers={
                "X-Error-Code": "INVALID_PAYLOAD"
            },
        )

    image_path = None
    video_path = None
    pdf_path = None

    try:

        if image and image.filename:

            logger.info(
                "Admin=%s uploading image=%s",
                admin.id,
                image.filename
            )

            image_path = await save_image(image)

        if video_file and video_file.filename:

            logger.info(
                "Admin=%s uploading video=%s",
                admin.id,
                video_file.filename
            )

            video_path = await save_video(video_file)

        if pdf_file and pdf_file.filename:

            logger.info(
                "Admin=%s uploading pdf=%s",
                admin.id,
                pdf_file.filename
            )

            pdf_path = await save_pdf(pdf_file)

    except ValueError as exc:

        logger.warning(
            "Invalid uploaded file: %s",
            str(exc)
        )

        raise HTTPException(
            status_code=400,
            detail=str(exc),
            headers={
                "X-Error-Code": "INVALID_FILE"
            },
        )

    return create_module(
        db=db,
        payload=payload,
        image_path=image_path,
        video_file_path=video_path,
        pdf_file_path=pdf_path,
    )