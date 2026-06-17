"""
schemas.py
================================================================================
CyberSafe Connect API Data Schemas
================================================================================

This module defines all Pydantic data models used by the
CyberSafe Connect backend API.

The schemas act as the validation and serialization layer between:

    - frontend applications
    - API routes
    - backend services
    - AI processing modules

Their role is to ensure:

    - data consistency
    - request validation
    - response standardization
    - API reliability
    - type safety

--------------------------------------------------------------------------------
WORKFLOW
--------------------------------------------------------------------------------

STEP 1 — Client Sends Request
    A frontend application sends JSON data to the API.

STEP 2 — Automatic Validation
    Pydantic validates:
        - required fields
        - field types
        - field constraints
        - message size limits

STEP 3 — Safe Data Conversion
    Data is converted into Python objects.

STEP 4 — Structured Response
    API responses are serialized into standardized JSON structures.

--------------------------------------------------------------------------------
SUPPORTED SCHEMAS
--------------------------------------------------------------------------------

UserMessage
    Represents a user question submitted to the chatbot.

ChatResponse
    Standardized chatbot response returned by the API.

--------------------------------------------------------------------------------
SECURITY FEATURES
--------------------------------------------------------------------------------

The validation layer helps protect against:

    - malformed requests
    - oversized payloads
    - empty messages
    - basic spam attempts
    - unexpected input types

--------------------------------------------------------------------------------
ROLE IN ARCHITECTURE
--------------------------------------------------------------------------------

This module is used by:

    - API routes
    - AI services
    - database services
    - future authentication systems
    - logging systems

All API input/output structures should be centralized here.

================================================================================
"""

# ==============================================================================
# IMPORTS
# ==============================================================================

from pydantic import BaseModel, Field
from datetime import datetime


# ==============================================================================
# USER MESSAGE SCHEMA
# ==============================================================================

class UserMessage(BaseModel):
    """
    Represents a chatbot request sent by a user.

    Attributes
    ----------
    user_id : str
        Unique identifier of the user.

        Defaults to "guest" for anonymous users.

    message : str
        User question or message submitted to the AI assistant.

        Constraints:
            - minimum length: 1 character
            - maximum length: 1000 characters
    """

    user_id: str = Field(
        default="guest",
        description="Unique identifier of the user."
    )

    message: str = Field(
        ...,
        min_length=1,
        max_length=1000,
        description="User message sent to the AI assistant."
    )


# ==============================================================================
# CHAT RESPONSE SCHEMA
# ==============================================================================

class ChatResponse(BaseModel):
    """
    Standard API response returned by the chatbot endpoint.

    Attributes
    ----------
    status : str
        Indicates request processing status.

        Possible values:
            - success
            - error

    response : str
        AI-generated response message.

    model : str
        Name of the AI model used to generate the response.

    timestamp : str
        ISO-formatted UTC timestamp indicating when
        the response was generated.
    """

    status: str

    response: str

    model: str

    timestamp: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )