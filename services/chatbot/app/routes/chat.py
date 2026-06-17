"""
chat.py
================================================================================
CyberSafe Connect Chat API Route
================================================================================

This module defines the main chatbot API endpoint used by the
CyberSafe Connect platform.

It acts as the communication layer between:

    - frontend clients
    - AI processing services
    - database services
    - validation schemas

The route is responsible for:

    - receiving user messages
    - validating incoming requests
    - generating AI responses
    - storing conversation history
    - returning structured API responses

--------------------------------------------------------------------------------
WORKFLOW
--------------------------------------------------------------------------------

STEP 1 — API Request Reception
    Receives a POST request from frontend applications.

STEP 2 — Request Validation
    Validates incoming JSON payload using Pydantic schemas.

STEP 3 — AI Processing
    Sends the validated user question to the AI service.

STEP 4 — Conversation Persistence
    Saves interaction data into the SQLite database.

STEP 5 — Response Serialization
    Returns a structured JSON response to the client.

--------------------------------------------------------------------------------
API ENDPOINTS
--------------------------------------------------------------------------------

POST /chat

    Main chatbot interaction endpoint.

--------------------------------------------------------------------------------
INPUTS
--------------------------------------------------------------------------------

Expected JSON Payload:

{
    "user_id": "guest",
    "message": "My WhatsApp account was hacked"
}

--------------------------------------------------------------------------------
OUTPUTS
--------------------------------------------------------------------------------

Success Response Example:

{
    "status": "success",
    "response": "You should immediately secure your account...",
    "model": "gpt-4.1-mini",
    "timestamp": "2026-05-13T10:30:00"
}

--------------------------------------------------------------------------------
SECURITY FEATURES
--------------------------------------------------------------------------------

- Automatic request validation
- Payload size limitation
- Structured error handling
- Centralized AI orchestration
- Safe database persistence

--------------------------------------------------------------------------------
ROLE IN ARCHITECTURE
--------------------------------------------------------------------------------

This module acts as the primary API gateway for chatbot interactions:

    Frontend
        ↓
    Chat Route
        ↓
    AI Service
        ↓
    Database Service

Future versions may support:

    - JWT authentication
    - rate limiting
    - multilingual routing
    - streaming responses
    - WebSocket support
    - user sessions

================================================================================
"""

# ==============================================================================
# IMPORTS
# ==============================================================================

import logging

from fastapi import APIRouter, HTTPException

from app.models.schemas import (
    UserMessage,
    ChatResponse
)

from app.services.ai_service import generate_ai_response

from app.services.database_service import (
    save_conversation
)

from app.core.config import DEFAULT_MODEL


# ==============================================================================
# LOGGER CONFIGURATION
# ==============================================================================

logging.basicConfig(level=logging.INFO)


# ==============================================================================
# ROUTER INITIALIZATION
# ==============================================================================

router = APIRouter()


# ==============================================================================
# CHAT ENDPOINT
# ==============================================================================

@router.post(
    "/chat",
    response_model=ChatResponse
)
async def chat(user_message: UserMessage):
    """
    Main chatbot interaction endpoint.

    Parameters
    ----------
    user_message : UserMessage
        Validated user request payload.

    Returns
    -------
    ChatResponse
        Structured AI response object.

    Raises
    ------
    HTTPException
        Raised when an internal processing error occurs.
    """

    try:

        logging.info(
            f"Received message from user: {user_message.user_id}"
        )

        # ----------------------------------------------------------------------
        # CLEAN USER INPUT
        # ----------------------------------------------------------------------

        question = user_message.message.strip()

        user_id = user_message.user_id.strip()


        # ----------------------------------------------------------------------
        # GENERATE AI RESPONSE
        # ----------------------------------------------------------------------

        ai_response = generate_ai_response(question)


        # ----------------------------------------------------------------------
        # SAVE CONVERSATION
        # ----------------------------------------------------------------------

        save_conversation(
            user_id=user_id,
            user_message=question,
            bot_response=ai_response,
            model_used=DEFAULT_MODEL
        )


        # ----------------------------------------------------------------------
        # RETURN STRUCTURED RESPONSE
        # ----------------------------------------------------------------------

        return ChatResponse(
            status="success",
            response=ai_response,
            model=DEFAULT_MODEL
        )

    except Exception as error:

        logging.error(
            f"Chat endpoint error: {error}"
        )

        raise HTTPException(
            status_code=500,
            detail="Internal server error."
        )