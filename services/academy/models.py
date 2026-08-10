"""
services/academy/models.py
================================================================================
CyberSafe Connect Academy Microservice
================================================================================

Database models for the Academy service.

Responsibilities:
    • Learning modules persistence
    • Quiz questions persistence
    • Answer choices persistence
    • Quiz results persistence
    • Database relationship definitions

This file MUST NOT contain:
    • Business logic
    • API routes
    • Authentication logic
    • File upload logic

Business logic belongs to:
    • services.py

API logic belongs to:
    • routes.py

Security logic belongs to:
    • security.py
================================================================================
"""

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)

from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from database import Base
from enums import TargetRole


class Module(Base):
    """
    Represents a cybersecurity learning module.

    A module may include:
        • Textual learning content
        • Cover image
        • External video URL
        • Uploaded video file
        • PDF attachment
        • Quiz questions

    Modules are filtered according to target audience.
    """

    __tablename__ = "modules"

    id = Column(Integer, primary_key=True, index=True)

    title = Column(
        String(200),
        nullable=False,
        index=True,
    )

    description = Column(
        Text,
        nullable=False,
    )

    content = Column(
        Text,
        nullable=False,
    )

    image_path = Column(
        String(255),
        nullable=True,
    )

    video_url = Column(
        String(255),
        nullable=True,
    )

    video_file_path = Column(
        String(255),
        nullable=True,
    )

    pdf_file_path = Column(
        String(255),
        nullable=True,
    )

    target_roles = Column(
        Enum(TargetRole, name="target_role_enum"),
        nullable=False,
        default=TargetRole.citizen,
    )

    display_order = Column(
        Integer,
        nullable=False,
        default=0,
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        index=True,
    )

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        index=True,
    )

    questions = relationship(
        "Question",
        back_populates="module",
        cascade="all, delete-orphan",
        order_by="Question.display_order",
    )

    quiz_results = relationship(
        "QuizResult",
        back_populates="module",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Module id={self.id} title={self.title}>"


class Question(Base):
    """
    Represents a quiz question attached to a module.

    Each question may contain:
        • Question text
        • Optional image
        • Multiple answer choices
    """

    __tablename__ = "questions"

    id = Column(Integer, primary_key=True, index=True)

    module_id = Column(
        Integer,
        ForeignKey(
            "modules.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    text = Column(
        Text,
        nullable=False,
    )

    image_path = Column(
        String(255),
        nullable=True,
    )

    display_order = Column(
        Integer,
        nullable=False,
        default=0,
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        index=True,
    )

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        index=True,
    )

    module = relationship(
        "Module",
        back_populates="questions",
    )

    choices = relationship(
        "Choice",
        back_populates="question",
        cascade="all, delete-orphan",
        order_by="Choice.id",
    )

    def __repr__(self) -> str:
        return f"<Question id={self.id} module={self.module_id}>"


class Choice(Base):
    """
    Represents a possible answer choice for a question.

    Multiple choices may exist,
    but business logic should guarantee
    only one correct answer.
    """

    __tablename__ = "choices"

    __table_args__ = (
        CheckConstraint(
            "length(text) > 0",
            name="ck_choice_text_not_empty",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)

    question_id = Column(
        Integer,
        ForeignKey(
            "questions.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    text = Column(
        String(255),
        nullable=False,
    )

    is_correct = Column(
        Boolean,
        nullable=False,
        default=False,
    )

    question = relationship(
        "Question",
        back_populates="choices",
    )

    def __repr__(self) -> str:
        return f"<Choice id={self.id} text={self.text}>"


class QuizResult(Base):
    """
    Stores a user's quiz completion result.

    Business rules:
        • One result per user per module
        • Score cannot be negative
        • Total questions must be greater than zero
        • Score cannot exceed total
    """

    __tablename__ = "quiz_results"

    __table_args__ = (

        UniqueConstraint(
            "user_id",
            "module_id",
            name="uq_quiz_user_module",
        ),

        CheckConstraint(
            "score >= 0",
            name="ck_score_positive",
        ),

        CheckConstraint(
            "total > 0",
            name="ck_total_positive",
        ),

        CheckConstraint(
            "score <= total",
            name="ck_score_not_greater_than_total",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(
        Integer,
        nullable=False,
        index=True,
    )

    module_id = Column(
        Integer,
        ForeignKey(
            "modules.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    score = Column(
        Integer,
        nullable=False,
    )

    total = Column(
        Integer,
        nullable=False,
    )

    completed_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        index=True,
    )

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        index=True,
    )

    module = relationship(
        "Module",
        back_populates="quiz_results",
    )

    def __repr__(self) -> str:
        return (
            f"<QuizResult user={self.user_id} "
            f"module={self.module_id} "
            f"score={self.score}/{self.total}>"
        )