"""
config.py
================================================================================
CyberSafe Connect Configuration Module
================================================================================

This module centralizes all global configuration variables used across
the CyberSafe Connect backend application.

It is responsible for:

    - Loading environment variables from .env
    - Managing API credentials
    - Defining application-wide constants
    - Centralizing model configuration
    - Providing secure access to sensitive settings

The goal of this module is to ensure:

    - maintainability
    - security
    - modularity
    - scalability
    - consistency across services

--------------------------------------------------------------------------------
WORKFLOW
--------------------------------------------------------------------------------

STEP 1 — Load Environment Variables
    Loads variables from the .env file using python-dotenv.

STEP 2 — Read Sensitive Credentials
    Retrieves API keys and configuration values securely.

STEP 3 — Define Global Constants
    Sets reusable constants for AI models, database paths,
    API metadata, and application behavior.

STEP 4 — Provide Shared Access
    Makes configuration values available to all backend modules.

--------------------------------------------------------------------------------
ENVIRONMENT VARIABLES
--------------------------------------------------------------------------------

OPENAI_API_KEY
    API key used for OpenAI model access.

APP_NAME
    Name of the application.

APP_VERSION
    Current backend version.

DATABASE_PATH
    SQLite database location.

DEFAULT_MODEL
    Default OpenAI model used for AI responses.

--------------------------------------------------------------------------------
OUTPUTS
--------------------------------------------------------------------------------

Exports:

    OPENAI_API_KEY : str
        OpenAI API credential.

    APP_NAME : str
        Backend application name.

    APP_VERSION : str
        Current backend version.

    DATABASE_PATH : str
        SQLite database file path.

    DEFAULT_MODEL : str
        Default AI model identifier.

--------------------------------------------------------------------------------
SECURITY NOTES
--------------------------------------------------------------------------------

- Sensitive credentials must NEVER be hardcoded.
- All secrets must be stored inside .env.
- .env must be excluded from Git using .gitignore.
- API keys should be rotated periodically.

--------------------------------------------------------------------------------
ROLE IN ARCHITECTURE
--------------------------------------------------------------------------------

This module acts as the central configuration layer for:

    - AI services
    - Database services
    - API routes
    - Logging systems
    - Future authentication modules

All backend services should import configuration values from here.

================================================================================
"""

# ==============================================================================
# IMPORTS
# ==============================================================================

import os
from dotenv import load_dotenv


# ==============================================================================
# ENVIRONMENT LOADING
# ==============================================================================

load_dotenv()


# ==============================================================================
# APPLICATION METADATA
# ==============================================================================

APP_NAME = "CyberSafe Connect API"

APP_VERSION = "1.0.0"

APP_DESCRIPTION = (
    "AI-powered cybersecurity and digital law assistant platform "
    "for citizens and organizations in Cameroon."
)


# ==============================================================================
# OPENAI CONFIGURATION
# ==============================================================================

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

DEFAULT_MODEL = "gpt-4.1-mini"


# ==============================================================================
# DATABASE CONFIGURATION
# ==============================================================================

DATABASE_PATH = "app/database/chatbot.db"


# ==============================================================================
# SECURITY CONFIGURATION
# ==============================================================================

MAX_MESSAGE_LENGTH = 1000

ENABLE_LOGGING = True


# ==============================================================================
# VALIDATION
# ==============================================================================

if not OPENAI_API_KEY:
    raise ValueError(
        "OPENAI_API_KEY is missing in the environment variables."
    )