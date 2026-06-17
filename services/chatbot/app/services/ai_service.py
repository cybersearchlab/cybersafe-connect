"""
ai_service.py
================================================================================
CyberSafe Connect AI Processing Service
================================================================================

This module is responsible for all AI-related operations inside the
CyberSafe Connect platform.

It acts as the intelligence orchestration layer between:

    - user requests
    - FAQ knowledge retrieval
    - system prompts
    - OpenAI language models

The service is designed to provide:

    - cybersecurity assistance
    - digital law guidance
    - scam awareness
    - phishing detection support
    - safe and contextual AI responses

--------------------------------------------------------------------------------
WORKFLOW
--------------------------------------------------------------------------------

STEP 1 — User Question Reception
    Receives the user's message from the API route.

STEP 2 — FAQ Context Retrieval
    Retrieves the most relevant FAQ entries from the FAQ service.

STEP 3 — Prompt Construction
    Combines:
        - system instructions
        - FAQ contextual information
        - user question

STEP 4 — OpenAI API Request
    Sends the structured prompt to the language model.

STEP 5 — AI Response Generation
    Receives and formats the generated response.

STEP 6 — Error Handling
    Captures API failures and returns safe fallback responses.

--------------------------------------------------------------------------------
INPUTS
--------------------------------------------------------------------------------

user_question : str
    User message submitted to the chatbot.

Example:

    "My Facebook account was hacked. What should I do?"

--------------------------------------------------------------------------------
OUTPUTS
--------------------------------------------------------------------------------

Returns:

    str
        AI-generated cybersecurity or legal guidance response.

Example:

    "You should immediately change your password..."

--------------------------------------------------------------------------------
SECURITY FEATURES
--------------------------------------------------------------------------------

This service includes:

    - contextual FAQ filtering
    - prompt modularization
    - centralized AI configuration
    - controlled system instructions
    - reduced hallucination risk
    - safe fallback responses

--------------------------------------------------------------------------------
ROLE IN ARCHITECTURE
--------------------------------------------------------------------------------

This module acts as the central AI orchestration layer:

    API Route
        ↓
    AI Service
        ↓
    FAQ Service
        ↓
    OpenAI API

Future versions may integrate:

    - RAG pipelines
    - embeddings
    - vector databases
    - legal document retrieval
    - phishing URL analysis
    - multilingual AI support

================================================================================
"""

# ==============================================================================
# IMPORTS
# ==============================================================================

import logging

from openai import OpenAI

from app.core.config import (
    OPENAI_API_KEY,
    DEFAULT_MODEL
)

from app.core.prompts import (
    CYLA_SYSTEM_PROMPT,
    FALLBACK_RESPONSE,
    SYSTEM_ERROR_RESPONSE
)

from app.services.faq_service import build_faq_context


# ==============================================================================
# LOGGER CONFIGURATION
# ==============================================================================

logging.basicConfig(level=logging.INFO)


# ==============================================================================
# OPENAI CLIENT INITIALIZATION
# ==============================================================================

client = OpenAI(api_key=OPENAI_API_KEY)


# ==============================================================================
# BUILD COMPLETE AI PROMPT
# ==============================================================================

def build_ai_prompt(user_question: str) -> str:
    """
    Build the final AI prompt using:
        - FAQ contextual knowledge
        - user question

    Parameters
    ----------
    user_question : str
        User message submitted to the chatbot.

    Returns
    -------
    str
        Final structured prompt sent to the AI model.
    """

    faq_context = build_faq_context(user_question)

    final_prompt = f"""
Cybersecurity and legal contextual information:

{faq_context}

User question:
{user_question}
"""

    return final_prompt


# ==============================================================================
# GENERATE AI RESPONSE
# ==============================================================================

def generate_ai_response(user_question: str) -> str:
    """
    Generate an AI response using OpenAI language models.

    Parameters
    ----------
    user_question : str
        User message submitted to the chatbot.

    Returns
    -------
    str
        AI-generated response.

    Security Notes
    --------------
    - Uses centralized system prompts
    - Injects only relevant FAQ context
    - Uses fallback responses on failure
    """

    try:

        logging.info(
            "Generating AI response for user question."
        )

        final_prompt = build_ai_prompt(user_question)

        response = client.chat.completions.create(
            model=DEFAULT_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": CYLA_SYSTEM_PROMPT
                },
                {
                    "role": "user",
                    "content": final_prompt
                }
            ],
            temperature=0.5,
            max_tokens=700
        )

        ai_response = (
            response
            .choices[0]
            .message
            .content
            .strip()
        )

        logging.info(
            "AI response generated successfully."
        )

        return ai_response

    except Exception as error:

        logging.error(
            f"AI generation error: {error}"
        )

        return SYSTEM_ERROR_RESPONSE