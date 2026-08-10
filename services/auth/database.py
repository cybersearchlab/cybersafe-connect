"""
================================================================================
MODULE: database.py
================================================================================

CyberSafe Connect - Authentication Service Database Configuration
================================================================================

OVERVIEW
--------

This module configures the asynchronous database layer for the authentication
service using SQLAlchemy asyncpg driver.

ARCHITECTURE CONTEXT
--------------------

This module sits between the application service and the PostgreSQL database.

    ┌─────────────────────────────────────────────────────────────────────────┐
    │                      Application Layer                                  │
    │  ┌─────────────────────────────────────────────────────────────────┐    │
    │  │  routes.py │ services.py │ security.py │ dependencies.py        │    │
    │  └─────────────────────────────────────────────────────────────────┘    │
    │                                   │                                     │
    │                                   ▼                                     │
    │  ┌─────────────────────────────────────────────────────────────────┐    │
    │  │                      database.py                                │    │
    │  │  (AsyncEngine, AsyncSession, Connection Pool, Base)             │    │
    │  └─────────────────────────────────────────────────────────────────┘    │
    │                                   │                                     │
    │                                   ▼                                     │
    │  ┌─────────────────────────────────────────────────────────────────┐    │
    │  │                    PostgreSQL Database                          │    │
    │  │              (cybersafe_auth)                                   │    │
    │  └─────────────────────────────────────────────────────────────────┘    │
    └─────────────────────────────────────────────────────────────────────────┘

SECURITY BOUNDARIES
-------------------

This module implements the following security controls:

1. Connection Pool Isolation
   - Each request gets its own session
   - Sessions are independent and isolated

2. Stale Connection Detection
   - pool_pre_ping: Verify connections before use

3. Connection Recycling
   - pool_recycle: 3600 seconds

4. Timeout Protection
   - timeout: 10 seconds

5. Transaction Safety
   - autocommit=False: Explicit commits only
   - autoflush=False: Explicit flush only

================================================================================
OWASP API SECURITY TOP 10 (2023) COMPLIANCE
================================================================================

| #   | Category                               | Status  | Implementation                     |
|-----|----------------------------------------|---------|------------------------------------|
| 4   | Unrestricted Resource Consumption      | Ok      | Connection pool limits             |
| 8   | Security Misconfiguration              | Ok      | Pool size, timeouts, pre-ping      |
| 9   | Improper Inventory Management          | Ok      | Centralized database configuration |

================================================================================
"""

# =============================================================================
# STANDARD LIBRARY IMPORTS
# =============================================================================

import logging

# =============================================================================
# THIRD-PARTY IMPORTS
# =============================================================================

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import declarative_base

# =============================================================================
# INTERNAL IMPORTS
# =============================================================================

from config import (
    DATABASE_URL,
    DATABASE_POOL_SIZE,
    DATABASE_MAX_OVERFLOW,
    DATABASE_POOL_TIMEOUT,
    DATABASE_ECHO,
    ENVIRONMENT,
)

# =============================================================================
# LOGGER CONFIGURATION
# =============================================================================

logger = logging.getLogger(__name__)


# =============================================================================
# ASYNC ENGINE
# =============================================================================

def create_async_engine_instance():
    """
    Create and configure the asynchronous SQLAlchemy database engine.

    Converts postgresql:// to postgresql+asyncpg:// for async support.

    Security Features:
    ------------------
    - pool_pre_ping: Verify connections before use
    - pool_recycle: Recycle connections after 1 hour
    - timeout: Prevent hanging connections (asyncpg)

    OWASP Compliance:
    - API4: Unrestricted Resource Consumption
    - API8: Security Misconfiguration

    Returns:
        AsyncEngine: SQLAlchemy async database engine

    Raises:
        SQLAlchemyError: If engine creation fails
    """
    async_database_url = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://")

    echo_enabled = DATABASE_ECHO
    if ENVIRONMENT == "production":
        echo_enabled = False

    logger.info(f"Creating async database engine for environment: {ENVIRONMENT}")

    try:
        engine_instance = create_async_engine(
            async_database_url,
            pool_size=DATABASE_POOL_SIZE,
            max_overflow=DATABASE_MAX_OVERFLOW,
            pool_timeout=DATABASE_POOL_TIMEOUT,
            pool_pre_ping=True,
            pool_recycle=3600,
            echo=echo_enabled,
            connect_args={
                "timeout": 10,  # asyncpg uses "timeout"
                # "application_name" supprimé - non supporté par asyncpg
            }
        )
        logger.info(" Async database engine created successfully")
        return engine_instance
    except Exception as e:
        logger.error(f" Failed to create async engine: {str(e)}")
        raise


# =============================================================================
# ASYNC SESSION FACTORY
# =============================================================================

def create_async_session_factory():
    """
    Create the asynchronous SQLAlchemy session factory.

    Session Configuration:
    ----------------------
    autocommit: bool = False - Prevent accidental commits
    autoflush: bool = False - Explicit flush only
    expire_on_commit: bool = False - Keep objects usable after commit

    Security Rationale:
    ------------------
    - autocommit=False: Ensures transaction safety
    - autoflush=False: Explicit control over data persistence

    Returns:
        async_sessionmaker: SQLAlchemy async session factory
    """
    logger.info("Creating async session factory")

    return async_sessionmaker(
        async_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )


# =============================================================================
# CREATE ENGINE AND SESSION
# =============================================================================

async_engine = create_async_engine_instance()
AsyncSessionLocal = create_async_session_factory()


# =============================================================================
# BASE DECLARATIVE CLASS
# =============================================================================

Base = declarative_base()
"""
Base class for all SQLAlchemy ORM models.

All model classes should inherit from this Base class.

Example:
    class User(Base):
        __tablename__ = "users"
        id = Column(Integer, primary_key=True)
        email = Column(String, unique=True, nullable=False)
"""


# =============================================================================
# DATABASE DEPENDENCY
# =============================================================================

async def get_async_db():
    """
    FastAPI dependency for obtaining an asynchronous database session.

    Usage:
        @app.get("/users")
        async def get_users(db: AsyncSession = Depends(get_async_db)):
            result = await db.execute(select(User))
            return result.scalars().all()

    Lifecycle:
        1. Session is created
        2. Session is yielded to the route handler
        3. Session is automatically closed after the request

    Security Considerations:
    -----------------------
    - Sessions are isolated per request
    - Sessions are closed even if an exception occurs
    - Prevents connection leaks

    OWASP Compliance:
    - API4: Unrestricted Resource Consumption (pool limits)
    - API8: Security Misconfiguration

    Yields:
        AsyncSession: SQLAlchemy async database session
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            logger.debug("Async database session yielded")
        except Exception as e:
            logger.error(f" Database session error: {str(e)}")
            await session.rollback()
            raise
        finally:
            await session.close()
            logger.debug("Async database session closed")


# =============================================================================
# DATABASE INITIALIZATION
# =============================================================================

async def init_database() -> None:
    """
    Initialize the database schema.

    This function creates all tables defined in the models.
    Should only be called in development environment.

    Security Considerations:
    -----------------------
    - In production, use Alembic migrations
    - Never use in production (risk of data loss)

    Raises:
        RuntimeError: If called in production environment
    """
    if ENVIRONMENT == "production":
        raise RuntimeError(
            "init_database() cannot be called in production. "
            "Use Alembic migrations instead."
        )

    logger.info("Creating database tables (development mode)...")

    try:
        async with async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info(" Database tables created successfully")
    except Exception as e:
        logger.error(f" Failed to create tables: {str(e)}")
        raise


# =============================================================================
# DATABASE CONNECTION TEST
# =============================================================================

async def test_connection() -> bool:
    """
    Test the database connection.

    Returns:
        bool: True if connection is successful, False otherwise
    """
    try:
        from sqlalchemy import text

        async with AsyncSessionLocal() as db:
            await db.execute(text("SELECT 1"))
            logger.info(" Database connection test successful")
            return True
    except Exception as e:
        logger.error(f" Database connection test failed: {str(e)}")
        return False


# =============================================================================
# SECURITY COMPLIANCE SUMMARY
# =============================================================================
#
# OWASP API Security Top 10 (2023):
#
# API4: Unrestricted Resource Consumption
#    - Connection pool limits (pool_size, max_overflow)
#    - Timeout protection (pool_timeout, connect_timeout)
#    - Connection recycling (pool_recycle)
#
# API8: Security Misconfiguration
#    - Connection verification (pool_pre_ping)
#    - Session isolation (autocommit=False)
#    - Explicit transaction control (autoflush=False)
#    - Environment-aware logging
#    - SQLite forbidden in production (enforced by config.py)
#
# API9: Improper Inventory Management
#    - Centralized database configuration
#    - Connection pooling with proper limits
#    - Session lifecycle management
#
# =============================================================================


# =============================================================================
# MAIN (for testing)
# =============================================================================

if __name__ == "__main__":
    """
    Run database configuration validation directly.

    Usage:
        python database.py

    This prints the configuration summary and tests the connection.
    """
    import asyncio

    print("=" * 80)
    print(" DATABASE CONFIGURATION SUMMARY")
    print("=" * 80)
    print(f"  Environment:      {ENVIRONMENT}")
    print(f"  Database URL:     {DATABASE_URL[:40]}...")
    print(f"  Pool Size:        {DATABASE_POOL_SIZE}")
    print(f"  Max Overflow:     {DATABASE_MAX_OVERFLOW}")
    print(f"  Pool Timeout:     {DATABASE_POOL_TIMEOUT}s")
    print(f"  Pool Pre-Ping:    Enabled")
    print(f"  Pool Recycle:     3600s")
    print(f"  Connect Timeout:  10s")
    print(f"  SQL Echo:         {DATABASE_ECHO}")
    print(f"  Async Support:    Available")
    print("=" * 80)

    # Test connection
    result = asyncio.run(test_connection())
    if result:
        print(" Database connection successful!")
    else:
        print(" Database connection failed!")

    print("=" * 80)