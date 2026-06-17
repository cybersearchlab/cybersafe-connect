"""
faq_service.py
================================================================================
CyberSafe Connect FAQ Intelligence Service
================================================================================

This module is responsible for managing and retrieving FAQ knowledge
used by the CyberSafe Connect AI assistant.

It acts as the first-level intelligence layer of the chatbot by:

    - loading cybersecurity and legal FAQ data
    - searching for relevant questions
    - retrieving contextual answers
    - reducing unnecessary AI token usage
    - improving response precision

Instead of injecting the entire FAQ knowledge base into the LLM prompt,
this service selects only the most relevant entries related to the
user's question.

This architecture is the foundation for future:

    - semantic search
    - vector databases
    - embeddings
    - Retrieval-Augmented Generation (RAG)
    - legal knowledge indexing

--------------------------------------------------------------------------------
WORKFLOW
--------------------------------------------------------------------------------

STEP 1 — FAQ Loading
    Loads the FAQ dataset from the JSON knowledge base.

STEP 2 — User Query Reception
    Receives the user's question from the chatbot service.

STEP 3 — Keyword Matching
    Performs basic similarity matching between the user question
    and stored FAQ questions.

STEP 4 — Relevance Ranking
    Computes similarity scores and ranks FAQ entries.

STEP 5 — Context Selection
    Returns only the most relevant FAQ items.

STEP 6 — AI Context Injection
    Selected FAQ results are injected into the AI prompt.

--------------------------------------------------------------------------------
INPUTS
--------------------------------------------------------------------------------

FAQ FILE:

    app/data/faq.json

Expected JSON structure:

[
    {
        "question": "...",
        "answer": "..."
    }
]

Function Inputs:

    user_question : str
        User message submitted to the chatbot.

    top_k : int
        Number of FAQ entries to return.

--------------------------------------------------------------------------------
OUTPUTS
--------------------------------------------------------------------------------

Returns:

    list[dict]
        List of the most relevant FAQ entries.

Example:

[
    {
        "question": "...",
        "answer": "..."
    }
]

--------------------------------------------------------------------------------
SECURITY NOTES
--------------------------------------------------------------------------------

- Limits unnecessary prompt injection
- Reduces exposure of internal knowledge base
- Prevents excessive token consumption
- Improves prompt efficiency
- Reduces hallucination risk by narrowing context

--------------------------------------------------------------------------------
ROLE IN ARCHITECTURE
--------------------------------------------------------------------------------

This module acts as the knowledge retrieval layer between:

    API Routes
        ↓
    FAQ Service
        ↓
    AI Service
        ↓
    OpenAI Model

It is a core component of the future intelligent legal-cybersecurity
assistant architecture.

--------------------------------------------------------------------------------
FUTURE IMPROVEMENTS
--------------------------------------------------------------------------------

Future versions may include:

    - semantic similarity search
    - sentence embeddings
    - vector databases
    - multilingual search
    - typo tolerance
    - legal article indexing
    - phishing pattern classification

================================================================================
"""

# ==============================================================================
# IMPORTS
# ==============================================================================

import json
import logging
from difflib import SequenceMatcher


# ==============================================================================
# FAQ FILE PATH
# ==============================================================================

FAQ_PATH = "app/data/faq.json"


# ==============================================================================
# LOGGER CONFIGURATION
# ==============================================================================

logging.basicConfig(level=logging.INFO)


# ==============================================================================
# LOAD FAQ DATA
# ==============================================================================

def load_faq() -> list:
    """
    Load the FAQ knowledge base from the JSON file.

    Returns
    -------
    list
        List of FAQ entries.

    Raises
    ------
    Exception
        Raised if the FAQ file cannot be loaded.
    """

    try:
        with open(FAQ_PATH, "r", encoding="utf-8") as file:
            faq_data = json.load(file)

        logging.info("FAQ knowledge base loaded successfully.")

        return faq_data

    except Exception as error:
        logging.error(f"Failed to load FAQ file: {error}")

        return []


# ==============================================================================
# COMPUTE TEXT SIMILARITY
# ==============================================================================

def compute_similarity(text1: str, text2: str) -> float:
    """
    Compute similarity ratio between two strings.

    Parameters
    ----------
    text1 : str
        First text string.

    text2 : str
        Second text string.

    Returns
    -------
    float
        Similarity score between 0 and 1.
    """

    return SequenceMatcher(
        None,
        text1.lower(),
        text2.lower()
    ).ratio()


# ==============================================================================
# SEARCH RELEVANT FAQ ENTRIES
# ==============================================================================

def search_faq(user_question: str, top_k: int = 3) -> list:
    """
    Search for the most relevant FAQ entries related to the user's question.

    Parameters
    ----------
    user_question : str
        User message submitted to the chatbot.

    top_k : int
        Maximum number of FAQ entries to return.

    Returns
    -------
    list
        List of the most relevant FAQ entries sorted by similarity.

    Example
    -------
    [
        {
            "question": "...",
            "answer": "..."
        }
    ]
    """

    faq_data = load_faq()

    scored_results = []

    for item in faq_data:

        question = item.get("question", "")
        answer = item.get("answer", "")

        similarity_score = compute_similarity(
            user_question,
            question
        )

        scored_results.append({
            "question": question,
            "answer": answer,
            "score": similarity_score
        })

    sorted_results = sorted(
        scored_results,
        key=lambda x: x["score"],
        reverse=True
    )

    top_results = sorted_results[:top_k]

    logging.info(
        f"Found {len(top_results)} relevant FAQ entries."
    )

    return top_results


# ==============================================================================
# BUILD FAQ CONTEXT
# ==============================================================================

def build_faq_context(user_question: str) -> str:
    """
    Build a contextual FAQ block for AI prompt injection.

    Parameters
    ----------
    user_question : str
        User message submitted to the chatbot.

    Returns
    -------
    str
        Structured FAQ context string.
    """

    relevant_faq = search_faq(user_question)

    if not relevant_faq:
        return "No relevant FAQ entries found."

    context = (
        "Relevant cybersecurity and legal FAQ information:\n\n"
    )

    for item in relevant_faq:

        context += (
            f"Q: {item['question']}\n"
            f"A: {item['answer']}\n\n"
        )

    return context