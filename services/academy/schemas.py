"""
services/academy/schemas.py
================================================================================
CyberSafe Connect Academy Microservice
================================================================================

Pydantic schemas for request validation and API responses.

Responsibilities:
    • Input validation
    • Response serialization
    • API contract enforcement
    • DTO definitions between routes and services

This file MUST NOT contain:
    • Database models
    • Business logic
    • Authentication logic

Business logic belongs to:
    • services.py

Database models belong to:
    • models.py
================================================================================
"""

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    field_validator,
)

from enums import TargetRole


# =============================================================================
# Choice Schemas
# =============================================================================

class ChoicePublic(BaseModel):
    """
    Public choice exposed to end users.
    """

    model_config = ConfigDict(
        from_attributes=True,
        extra="forbid",
    )

    id: int
    text: str


class ChoiceAdmin(BaseModel):
    """
    Administrative view of a quiz choice.
    """

    model_config = ConfigDict(
        from_attributes=True,
        extra="forbid",
    )

    id: int
    text: str
    is_correct: bool


class ChoiceInput(BaseModel):
    """
    Choice creation payload.
    """

    model_config = ConfigDict(extra="forbid")

    text: str = Field(
        min_length=1,
        max_length=255,
    )

    is_correct: bool = False


# =============================================================================
# Question Schemas
# =============================================================================

class QuestionPublic(BaseModel):
    """
    Public question schema.
    """

    model_config = ConfigDict(
        from_attributes=True,
        extra="forbid",
    )

    id: int
    text: str
    image_path: str | None
    display_order: int
    choices: list[ChoicePublic]


class QuestionAdmin(BaseModel):
    """
    Administrative question schema.
    """

    model_config = ConfigDict(
        from_attributes=True,
        extra="forbid",
    )

    id: int
    text: str
    image_path: str | None
    display_order: int
    choices: list[ChoiceAdmin]


class QuestionInput(BaseModel):
    """
    Question creation payload.
    """

    model_config = ConfigDict(extra="forbid")

    text: str = Field(
        min_length=1,
    )

    display_order: int = Field(
        default=0,
        ge=0,
    )

    choices: list[ChoiceInput] = Field(
        min_length=2,
    )

    @field_validator("choices")
    @classmethod
    def validate_correct_answer(cls, choices):

        correct_answers = sum(
            1 for choice in choices
            if choice.is_correct
        )

        if correct_answers != 1:
            raise ValueError(
                "Question must contain exactly one correct answer."
            )

        return choices


# =============================================================================
# Module Schemas
# =============================================================================

class ModuleListItem(BaseModel):
    """
    Lightweight module response.
    """

    model_config = ConfigDict(
        from_attributes=True,
        extra="forbid",
    )

    id: int
    title: str
    description: str

    display_order: int

    question_count: int

    image_path: str | None
    video_url: str | None
    video_file_path: str | None
    pdf_file_path: str | None

    target_roles: TargetRole


class ModuleDetail(BaseModel):
    """
    Full module response.
    """

    model_config = ConfigDict(
        from_attributes=True,
        extra="forbid",
    )

    id: int
    title: str
    description: str
    content: str

    display_order: int

    image_path: str | None
    video_url: str | None
    video_file_path: str | None
    pdf_file_path: str | None

    target_roles: TargetRole

    questions: list[QuestionPublic]


class ModuleCreateRequest(BaseModel):
    """
    Module creation request payload.
    """

    model_config = ConfigDict(extra="forbid")

    title: str = Field(
        min_length=3,
        max_length=200,
    )

    description: str = Field(
        min_length=10,
    )

    content: str = Field(
        min_length=10,
    )

    video_url: HttpUrl | None = None

    target_roles: TargetRole = TargetRole.citizen

    display_order: int = Field(
        default=0,
        ge=0,
    )

    questions: list[QuestionInput] = Field(
        default_factory=list,
    )

    @field_validator("video_url")
    @classmethod
    def empty_url_to_none(cls, value):

        if value is not None and str(value).strip() == "":
            return None

        return value


# =============================================================================
# Quiz Schemas
# =============================================================================

class QuizSubmitRequest(BaseModel):
    """
    Quiz submission payload.
    """

    model_config = ConfigDict(extra="forbid")

    module_id: int = Field(gt=0)

    answers: dict[str, int] = Field(
        description="question_id -> choice_id",
    )

    @field_validator("answers")
    @classmethod
    def validate_answers(cls, value):

        if not value:
            raise ValueError(
                "Answers payload cannot be empty."
            )

        return value


class QuizAnswerDetail(BaseModel):
    """
    Individual quiz answer result.
    """

    question_id: int
    selected_choice_id: int
    is_correct: bool


class QuizSubmitResponse(BaseModel):
    """
    Quiz submission response.
    """

    score: int
    total: int
    passed: bool
    details: list[QuizAnswerDetail]
    message: str


class ProgressResponse(BaseModel):
    """
    User completed modules.
    """

    completed: list[int]