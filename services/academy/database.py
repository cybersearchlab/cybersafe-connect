"""
services/academy/database.py
================================================================================
CyberSafe Connect Academy Microservice
================================================================================

Database initialization layer.

Responsibilities:
    • Database engine creation
    • SQLAlchemy session management
    • Base ORM declaration
    • Dependency injection for database sessions

This file MUST NOT contain:
    • Business logic
    • API routes
    • Authentication logic

Business logic belongs to:
    • services.py

API logic belongs to:
    • routes.py

================================================================================
"""

from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool

from config import DATABASE_URL


# =============================================================================
# SQLite configuration
# =============================================================================

connect_args = {}
pool_kwargs = {}


if DATABASE_URL.startswith("sqlite"):

    connect_args = {
        "check_same_thread": False
    }

    db_path = DATABASE_URL.replace(
        "sqlite:///",
        ""
    )

    if db_path and not db_path.startswith(":"):
        Path(db_path).parent.mkdir(
            parents=True,
            exist_ok=True,
        )

    if (
        ":memory:" in DATABASE_URL
        or DATABASE_URL == "sqlite://"
    ):
        pool_kwargs["poolclass"] = StaticPool


# =============================================================================
# Database Engine
# =============================================================================

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    future=True,
    pool_pre_ping=True,
    **pool_kwargs,
)


# =============================================================================
# Session Factory
# =============================================================================

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)


# =============================================================================
# Base ORM Class
# =============================================================================

Base = declarative_base()