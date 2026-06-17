"""
database_service.py
================================================================================
CyberSafe Connect Database Management Service
================================================================================

This module is responsible for all database-related operations within
the CyberSafe Connect backend infrastructure.

It acts as the persistence layer of the platform and manages:

    - database initialization
    - conversation storage
    - conversation history retrieval
    - database connections
    - future persistent cybersecurity records

The current implementation uses SQLite for simplicity and rapid MVP
deployment, while maintaining a structure compatible with future
migration to PostgreSQL or other production-grade databases.

--------------------------------------------------------------------------------
WORKFLOW
--------------------------------------------------------------------------------

STEP 1 — Database Initialization
    Creates the SQLite database and required tables if they do not exist.

STEP 2 — User Interaction Storage
    Saves chatbot conversations and metadata into the database.

STEP 3 — Historical Retrieval
    Allows retrieval of previous user conversations.

STEP 4 — Logging and Monitoring
    Logs database operations and errors.

STEP 5 — Future Scalability
    Provides a modular database layer for future expansion.

--------------------------------------------------------------------------------
DATABASE TABLES
--------------------------------------------------------------------------------

conversations
    Stores chatbot interactions between users and CYLA.

Fields:

    id : INTEGER
        Auto-increment primary key.

    date_time : TEXT
        Timestamp of interaction.

    user_id : TEXT
        Unique identifier of the user.

    user_message : TEXT
        Message submitted by the user.

    bot_response : TEXT
        AI-generated response.

    model_used : TEXT
        AI model used for response generation.

--------------------------------------------------------------------------------
INPUTS
--------------------------------------------------------------------------------

save_conversation()

    user_id : str
        Unique user identifier.

    user_message : str
        Original user question.

    bot_response : str
        AI-generated response.

    model_used : str
        Name of AI model used.

--------------------------------------------------------------------------------
OUTPUTS
--------------------------------------------------------------------------------

Side Effects:

    - Creates SQLite database
    - Inserts conversation records
    - Logs database activity

Returns:

    None

--------------------------------------------------------------------------------
SECURITY NOTES
--------------------------------------------------------------------------------

- Uses parameterized SQL queries
- Prevents SQL injection risks
- Keeps database access centralized
- Supports future encryption integration
- Designed for secure migration to PostgreSQL

--------------------------------------------------------------------------------
ROLE IN ARCHITECTURE
--------------------------------------------------------------------------------

This module acts as the persistence layer between:

    API Routes
        ↓
    Database Service
        ↓
    SQLite Database

Future versions may support:

    - PostgreSQL
    - MongoDB
    - encrypted records
    - user authentication data
    - incident reports
    - legal case tracking
    - analytics dashboards

================================================================================
"""

# ==============================================================================
# IMPORTS
# ==============================================================================

import sqlite3
import logging

from datetime import datetime

from app.core.config import DATABASE_PATH


# ==============================================================================
# LOGGER CONFIGURATION
# ==============================================================================

logging.basicConfig(level=logging.INFO)


# ==============================================================================
# DATABASE CONNECTION
# ==============================================================================

def get_database_connection():
    """
    Create and return a SQLite database connection.

    Returns
    -------
    sqlite3.Connection
        Active SQLite connection object.
    """

    connection = sqlite3.connect(DATABASE_PATH)

    return connection


# ==============================================================================
# DATABASE INITIALIZATION
# ==============================================================================

def initialize_database():
    """
    Initialize the SQLite database and create required tables.

    Creates
    -------
    conversations table

    Returns
    -------
    None
    """

    try:

        connection = get_database_connection()

        cursor = connection.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS conversations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date_time TEXT NOT NULL,
                user_id TEXT NOT NULL,
                user_message TEXT NOT NULL,
                bot_response TEXT NOT NULL,
                model_used TEXT NOT NULL
            )
        """)

        connection.commit()

        logging.info(
            "Database initialized successfully."
        )

    except sqlite3.Error as error:

        logging.error(
            f"Database initialization error: {error}"
        )

    finally:

        connection.close()


# ==============================================================================
# SAVE CONVERSATION
# ==============================================================================

def save_conversation(
    user_id: str,
    user_message: str,
    bot_response: str,
    model_used: str
):
    """
    Save a chatbot conversation into the database.

    Parameters
    ----------
    user_id : str
        Unique identifier of the user.

    user_message : str
        Original user message.

    bot_response : str
        AI-generated response.

    model_used : str
        Name of the AI model used.

    Returns
    -------
    None
    """

    try:

        connection = get_database_connection()

        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO conversations (
                date_time,
                user_id,
                user_message,
                bot_response,
                model_used
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            datetime.utcnow().isoformat(),
            user_id,
            user_message,
            bot_response,
            model_used
        ))

        connection.commit()

        logging.info(
            f"Conversation saved for user: {user_id}"
        )

    except sqlite3.Error as error:

        logging.error(
            f"Database insertion error: {error}"
        )

    finally:

        connection.close()


# ==============================================================================
# GET USER CONVERSATION HISTORY
# ==============================================================================

def get_conversation_history(
    user_id: str,
    limit: int = 10
):
    """
    Retrieve the latest conversation history for a user.

    Parameters
    ----------
    user_id : str
        Unique identifier of the user.

    limit : int
        Maximum number of records to retrieve.

    Returns
    -------
    list
        List of conversation records.
    """

    try:

        connection = get_database_connection()

        cursor = connection.cursor()

        cursor.execute("""
            SELECT
                date_time,
                user_message,
                bot_response,
                model_used
            FROM conversations
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT ?
        """, (
            user_id,
            limit
        ))

        rows = cursor.fetchall()

        history = []

        for row in rows:

            history.append({
                "date_time": row[0],
                "user_message": row[1],
                "bot_response": row[2],
                "model_used": row[3]
            })

        logging.info(
            f"Retrieved conversation history for user: {user_id}"
        )

        return history

    except sqlite3.Error as error:

        logging.error(
            f"Database retrieval error: {error}"
        )

        return []

    finally:

        connection.close()