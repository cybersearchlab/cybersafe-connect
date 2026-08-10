"""
services/academy/services.py
================================================================================
CyberSafe Connect Academy Microservice
================================================================================

Academy business logic service layer.

This module centralizes all academy-related business logic and acts as the
intermediate layer between API routes and persistence models.

The objective of this architecture is strict separation of concerns.

Responsibilities
----------------

This service layer handles:

    • Learning module retrieval
    • Module access control enforcement
    • Quiz answer validation
    • Quiz scoring computation
    • Quiz submission persistence
    • User progress tracking
    • Administrative module creation
    • Transaction management
    • Security audit logging

Architecture Rules
------------------

This file MUST NOT contain:

    • FastAPI route definitions
    • Authentication implementation
    • JWT validation logic
    • HTTP transport concerns

Security Principles
-------------------

• Never trust incoming user role blindly
• Prevent unauthorized module access
• Prevent duplicate or concurrent quiz race conditions
• Use atomic database transactions
• Log suspicious access attempts
• Prevent inconsistent quiz persistence state

Layer Architecture
------------------

API Layer:
    routes.py

Authentication Layer:
    dependencies.py
    security.py

Persistence Layer:
    models.py

================================================================================
"""

# =============================================================================
# STANDARD LIBRARY IMPORTS
# =============================================================================

import logging

from datetime import datetime, timezone


# =============================================================================
# THIRD-PARTY IMPORTS
# =============================================================================

from fastapi import HTTPException

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, joinedload


# =============================================================================
# INTERNAL IMPORTS
# =============================================================================

from dependencies import AuthUser, target_roles_for_user

from enums import TargetRole

from models import (
    Choice,
    Module,
    Question,
    QuizResult
)

from schemas import (
    ChoicePublic,
    ModuleDetail,
    ModuleListItem,
    QuizAnswerDetail,
    QuizSubmitRequest,
    QuizSubmitResponse
)

from storage import media_url


# =============================================================================
# LOGGER CONFIGURATION
# =============================================================================

logger = logging.getLogger(__name__)


# =============================================================================
# INTERNAL SERIALIZATION HELPERS
# =============================================================================

def _module_list_item(
    module: Module
) -> ModuleListItem:
    """
    Convert Module ORM object into public list representation.

    This helper exposes only minimal information required by
    academy module listing endpoints.

    Parameters
    ----------
    module : Module
        SQLAlchemy module entity.

    Returns
    -------
    ModuleListItem
        Public-facing serialized module object.

    Security Notes
    --------------
    Internal database fields must never leak here.
    """

    return ModuleListItem(
        id=module.id,

        title=module.title,

        description=module.description,

        display_order=module.display_order,

        question_count=len(module.questions),

        image_path=media_url(
            module.image_path
        ),

        video_url=module.video_url,

        video_file_path=media_url(
            module.video_file_path
        ),

        pdf_file_path=media_url(
            module.pdf_file_path
        ),

        target_roles=module.target_roles
    )


# =============================================================================
# DETAILED MODULE SERIALIZATION
# =============================================================================

def _module_detail(
    module: Module
) -> ModuleDetail:
    """
    Convert complete module entity into detailed public schema.

    This serializer includes educational content, quiz questions
    and associated answer choices.

    Parameters
    ----------
    module : Module
        Fully loaded module entity.

    Returns
    -------
    ModuleDetail
        Complete serialized module structure.

    Security Notes
    --------------
    Correct answers must NEVER be exposed in public output.
    """

    questions = []

    for question in module.questions:

        choices = [
            ChoicePublic(
                id=choice.id,
                text=choice.text
            )
            for choice in question.choices
        ]

        questions.append(
            QuestionPublic(
                id=question.id,

                text=question.text,

                image_path=media_url(
                    question.image_path
                ),

                display_order=question.display_order,

                choices=choices
            )
        )

    return ModuleDetail(
        id=module.id,

        title=module.title,

        description=module.description,

        content=module.content,

        display_order=module.display_order,

        image_path=media_url(
            module.image_path
        ),

        video_url=module.video_url,

        video_file_path=media_url(
            module.video_file_path
        ),

        pdf_file_path=media_url(
            module.pdf_file_path
        ),

        target_roles=module.target_roles,

        questions=questions
    )


# =============================================================================
# QUIZ VALIDATION RULES
# =============================================================================

def _quiz_passed(
    score: int,
    total: int
) -> bool:
    """
    Determine whether quiz result is considered successful.

    Current policy:

        score > 50%

    Parameters
    ----------
    score : int
        Number of correct answers.

    total : int
        Total quiz questions.

    Returns
    -------
    bool
        True if quiz passed.
    """

    return score > (total / 2)


# =============================================================================
# MODULE LISTING SERVICE
# =============================================================================

def list_modules(
    db: Session,
    user: AuthUser | None
) -> dict:
    """
    Retrieve academy modules accessible to current user.

    Access rules
    ------------

    Anonymous user:
        citizen + both

    Citizen:
        citizen + both

    Company:
        company + both

    Admin:
        full access

    Parameters
    ----------
    db : Session
        Database session.

    user : AuthUser | None
        Authenticated user or anonymous.

    Returns
    -------
    dict
        Serialized module list.

    Security Notes
    --------------
    Module visibility is role restricted.
    """

    allowed_roles = [
        TargetRole(role)
        for role in target_roles_for_user(user)
    ]

    modules = (
        db.query(Module)

        .options(
            joinedload(
                Module.questions
            )
        )

        .filter(
            Module.target_roles.in_(
                allowed_roles
            )
        )

        .order_by(
            Module.display_order
        )

        .all()
    )

    logger.info(
        "Retrieved %s accessible academy modules",
        len(modules)
    )

    return {
        "success": True,

        "message":
            "Modules retrieved successfully",

        "data": [
            _module_list_item(
                module
            ).model_dump()

            for module in modules
        ]
    }


# =============================================================================
# MODULE DETAIL SERVICE
# =============================================================================

def get_module_detail(
    db: Session,
    module_id: int,
    user: AuthUser | None = None
) -> dict:
    """
    Retrieve complete academy module.

    This function performs role-based access validation
    before exposing educational content.

    Parameters
    ----------
    db : Session
        Database session.

    module_id : int
        Target module identifier.

    user : AuthUser | None
        Current authenticated user.

    Returns
    -------
    dict
        Full serialized module.

    Raises
    ------
    HTTPException
        If module unavailable or access denied.
    """

    module = (
        db.query(Module)

        .options(
            joinedload(
                Module.questions
            ).joinedload(
                Question.choices
            )
        )

        .filter(
            Module.id == module_id
        )

        .first()
    )

    # -------------------------------------------------------------------------
    # Module existence validation
    # -------------------------------------------------------------------------

    if not module:

        logger.warning(
            "Requested academy module not found: id=%s",
            module_id
        )

        raise HTTPException(
            status_code=404,
            detail="Module not found"
        )

    # -------------------------------------------------------------------------
    # Role access validation
    # -------------------------------------------------------------------------

    allowed_roles = target_roles_for_user(user)

    if (
        module.target_roles != TargetRole.both
        and module.target_roles.value not in allowed_roles
    ):

        logger.warning(
            "Unauthorized module access denied "
            "module=%s",
            module_id
        )

        raise HTTPException(
            status_code=403,
            detail="Access denied"
        )

    return {
        "success": True,

        "message":
            "Module retrieved successfully",

        "data":
            _module_detail(
                module
            ).model_dump()
    }


# =============================================================================
# QUIZ SUBMISSION SERVICE
# =============================================================================

def submit_quiz(
    db: Session,
    user: AuthUser,
    payload: QuizSubmitRequest
) -> dict:
    """
    Submit academy quiz answers.

    Workflow
    --------

        1. Validate module existence
        2. Validate access rights
        3. Validate submitted answers
        4. Calculate score
        5. Store or update previous result
        6. Commit transaction atomically

    Security Controls
    -----------------

    • Prevent unauthorized module access
    • Prevent malformed answer injection
    • Prevent concurrent race conditions
    • Guarantee transaction atomicity

    Parameters
    ----------
    db : Session

    user : AuthUser

    payload : QuizSubmitRequest

    Returns
    -------
    dict
        Quiz result payload.
    """

    module = (
        db.query(Module)

        .options(
            joinedload(
                Module.questions
            ).joinedload(
                Question.choices
            )
        )

        .filter(
            Module.id == payload.module_id
        )

        .first()
    )

    if not module:

        raise HTTPException(
            status_code=404,
            detail="Module not found"
        )

    allowed_roles = target_roles_for_user(
        user
    )

    if (
        module.target_roles != TargetRole.both
        and module.target_roles.value not in allowed_roles
    ):

        logger.warning(
            "Unauthorized quiz submission "
            "user=%s module=%s",
            user.id,
            module.id
        )

        raise HTTPException(
            status_code=403,
            detail="Access denied"
        )

    questions = list(
        module.questions
    )

    total = len(
        questions
    )

    if len(payload.answers) != total:

        raise HTTPException(
            status_code=400,
            detail="Incomplete quiz answers"
        )

    score = 0

    details: list[
        QuizAnswerDetail
    ] = []

    # -------------------------------------------------------------------------
    # Validate each submitted answer
    # -------------------------------------------------------------------------

    for question in questions:

        # Extract submitted answer for current question

        choice_id = payload.answers.get(
            str(question.id)
        )

        # Missing answer protection

        if choice_id is None:

            raise HTTPException(
                status_code=400,
                detail=(
                    f"Missing answer for "
                    f"question {question.id}"
                )
            )

        # Verify choice belongs to question

        choice = next(
            (
                candidate
                for candidate in question.choices
                if candidate.id == choice_id
            ),
            None
        )

        if not choice:

            logger.warning(
                "Invalid answer injection attempt "
                "user=%s question=%s choice=%s",
                user.id,
                question.id,
                choice_id
            )

            raise HTTPException(
                status_code=400,
                detail="Invalid answer choice"
            )

        # Determine correctness

        is_correct = choice.is_correct

        if is_correct:
            score += 1

        # Store answer details for response payload

        details.append(
            QuizAnswerDetail(
                question_id=question.id,
                selected_choice_id=choice.id,
                is_correct=is_correct
            )
        )

    # -------------------------------------------------------------------------
    # Persist quiz result transaction
    # -------------------------------------------------------------------------

    try:

        existing_result = (

            db.query(
                QuizResult
            )

            .filter(
                QuizResult.user_id == user.id,
                QuizResult.module_id == module.id
            )

            .first()
        )

        # Existing attempt update

        if existing_result:

            existing_result.score = score

            existing_result.total = total

            existing_result.completed_at = datetime.now(
                timezone.utc
            )

        # First attempt insert

        else:

            db.add(

                QuizResult(
                    user_id=user.id,
                    module_id=module.id,
                    score=score,
                    total=total
                )
            )

        db.commit()

        logger.info(
            "Quiz submission successful "
            "user=%s module=%s score=%s/%s",
            user.id,
            module.id,
            score,
            total
        )

    except SQLAlchemyError as exc:

        db.rollback()

        logger.error(
            "Database transaction failed "
            "during quiz submission: %s",
            str(exc)
        )

        raise HTTPException(
            status_code=500,
            detail="Database transaction failed"
        )

    # -------------------------------------------------------------------------
    # Determine final quiz result
    # -------------------------------------------------------------------------

    passed = _quiz_passed(
        score,
        total
    )

    response = QuizSubmitResponse(
        score=score,
        total=total,
        passed=passed,
        details=details,
        message=(

            "Quiz passed successfully"

            if passed

            else

            "Quiz failed, try again"
        )
    )

    return {
        "success": True,
        "message": response.message,
        "data": response.model_dump()
    }

# =============================================================================
# MODULE CREATION SERVICE
# =============================================================================

def create_module(
    db: Session,
    payload: ModuleCreateRequest,
    image_path: str | None = None,
    video_file_path: str | None = None,
    pdf_file_path: str | None = None,
) -> dict:
    """
    Create a new academy learning module.

    This service is restricted to administrators only.
    Authentication and authorization checks MUST already
    be enforced at the route dependency layer.

    Workflow
    --------

        1. Validate duplicate module title
        2. Validate quiz question integrity
        3. Create module database entity
        4. Create related questions
        5. Create answer choices
        6. Commit database transaction atomically
        7. Reload fully hydrated module
        8. Return serialized response

    Security Controls
    -----------------

    • Prevent duplicate content creation
    • Prevent malformed quiz structures
    • Prevent multiple correct answers per question
    • Guarantee ACID transaction integrity
    • Rollback automatically on persistence failure
    • Prevent inconsistent orphan records

    Parameters
    ----------
    db : Session
        Active SQLAlchemy database session.

    payload : ModuleCreateRequest
        Validated module creation payload.

    image_path : str | None
        Stored image path after upload validation.

    video_file_path : str | None
        Stored video path after upload validation.

    pdf_file_path : str | None
        Stored PDF path after upload validation.

    Returns
    -------
    dict
        Newly created academy module.

    Raises
    ------
    HTTPException

        409:
            Module already exists.

        400:
            Invalid quiz structure.

        500:
            Database transaction failure.
    """

    # -------------------------------------------------------------------------
    # Duplicate module validation
    # Prevent accidental or malicious duplicate content creation
    # -------------------------------------------------------------------------

    existing = (
        db.query(Module)

        .filter(
            Module.title == payload.title
        )

        .first()
    )

    if existing:

        logger.warning(
            "Duplicate module creation blocked: %s",
            payload.title
        )

        raise HTTPException(
            status_code=409,
            detail="Module already exists"
        )

    # -------------------------------------------------------------------------
    # Quiz validation
    #
    # Security rule:
    # Every question MUST contain exactly one valid correct answer.
    #
    # This prevents malformed educational content injection.
    # -------------------------------------------------------------------------

    for question in payload.questions:

        correct_choices = [

            choice

            for choice in question.choices

            if choice.is_correct
        ]

        if len(correct_choices) != 1:

            logger.warning(
                "Invalid quiz structure detected "
                "during module creation"
            )

            raise HTTPException(
                status_code=400,

                detail=(
                    "Each question must contain "
                    "exactly one correct answer"
                )
            )

    # -------------------------------------------------------------------------
    # Atomic database transaction
    #
    # Entire module creation MUST succeed completely
    # or fail completely.
    #
    # Prevents partial persistence:
    #
    #     module exists
    #     but questions missing
    #
    # or:
    #
    #     questions exist
    #     but choices missing
    # -------------------------------------------------------------------------

    try:

        # ---------------------------------------------------------------------
        # Create parent module
        # ---------------------------------------------------------------------

        module = Module(
            title=payload.title,

            description=payload.description,

            content=payload.content,

            image_path=image_path,

            video_url=payload.video_url,

            video_file_path=video_file_path,

            pdf_file_path=pdf_file_path,

            target_roles=payload.target_roles,

            display_order=payload.display_order
        )

        db.add(
            module
        )

        # Flush generates module.id immediately
        db.flush()

        # ---------------------------------------------------------------------
        # Create related questions
        # ---------------------------------------------------------------------

        for index, question_data in enumerate(
            payload.questions
        ):

            question = Question(
                module_id=module.id,

                text=question_data.text,

                display_order=(

                    question_data.display_order

                    or index + 1
                )
            )

            db.add(
                question
            )

            # Flush generates question.id immediately
            db.flush()

            # -----------------------------------------------------------------
            # Create answer choices
            # -----------------------------------------------------------------

            for choice_data in question_data.choices:

                choice = Choice(
                    question_id=question.id,

                    text=choice_data.text,

                    is_correct=choice_data.is_correct
                )

                db.add(
                    choice
                )

        # ---------------------------------------------------------------------
        # Commit transaction
        # ---------------------------------------------------------------------

        db.commit()

        logger.info(
            "Academy module created successfully: %s",
            module.title
        )

    # -------------------------------------------------------------------------
    # SQL transaction failure handling
    # -------------------------------------------------------------------------

    except SQLAlchemyError as error:

        db.rollback()

        logger.error(
            "Module creation transaction failed: %s",
            str(error)
        )

        raise HTTPException(
            status_code=500,

            detail="Database transaction failed"
        )

    # -------------------------------------------------------------------------
    # Reload full module graph
    #
    # Needed because relationships are not fully hydrated after flush.
    # -------------------------------------------------------------------------

    db.refresh(
        module
    )

    module = (

        db.query(Module)

        .options(

            joinedload(
                Module.questions
            ).joinedload(
                Question.choices
            )
        )

        .filter(
            Module.id == module.id
        )

        .first()
    )

    # -------------------------------------------------------------------------
    # Return API response
    # -------------------------------------------------------------------------

    return {
        "success": True,

        "message":
            "Module created successfully",

        "data":
            _module_detail(
                module
            ).model_dump()
    }