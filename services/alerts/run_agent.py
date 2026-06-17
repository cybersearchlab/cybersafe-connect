"""
run_agent.py
================================================================================
Cyber Threat Intelligence Monitoring Agent
================================================================================

This script implements the main operational workflow of the cyber threat
intelligence agent.

The agent continuously monitors newly published vulnerabilities,
stores them in a local SQLite database, identifies previously unseen
high-severity CVEs, and generates automated email notifications.

--------------------------------------------------------------------------------
WORKFLOW
--------------------------------------------------------------------------------

STEP 1 — Environment Initialization
    Loads runtime configuration and email credentials from .env file.

STEP 2 — Database Initialization
    Ensures SQLite database and CVE table exist.

STEP 3 — CVE Collection
    Fetches recent CVEs from external API (NVD).

STEP 4 — Persistence
    Stores CVEs into local SQLite database.

STEP 5 — Deduplication & Filtering
    Filters previously unseen HIGH/CRITICAL CVEs using state tracking.

STEP 6 — Alerting
    Sends email notifications for newly detected threats.

--------------------------------------------------------------------------------
INPUTS
--------------------------------------------------------------------------------

Environment variables (.env):
    - GMAIL_USER
    - GMAIL_APP_PASSWORD
    - EMAIL_TO
    - EMAIL_FROM_NAME (optional)

External modules:
    - collect_cves.py
    - duplicate.py
    - email_alert.py

Database:
    - cve_data.db

Parameters:
    - hours_back (int)
    - min_score (float)
    - dry_run (bool)

--------------------------------------------------------------------------------
OUTPUTS
--------------------------------------------------------------------------------

- Updated SQLite CVE database
- List of new HIGH/CRITICAL CVEs
- Email alerts via SMTP (Gmail)
- Structured execution logs
- Return dictionary:

    {
        "retrieved": int,
        "new_cves": int,
        "email_result": dict,
        "stats": dict
    }

--------------------------------------------------------------------------------
ALERTING STRATEGY
--------------------------------------------------------------------------------

Only CVEs matching:
    - NOT previously processed
    - severity HIGH or CRITICAL
    - score >= min_score

--------------------------------------------------------------------------------
"""

# ==============================================================================
# Imports
# ==============================================================================

import os
import logging

from dotenv import load_dotenv

from email_alert import send_email
from collect_cves import fetch_recent_cves, save_cves, init_db
from duplicate import get_new_high_critical_cves

# ==============================================================================
# Logging
# ==============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ==============================================================================
# Environment
# ==============================================================================

load_dotenv()

GMAIL_USER = os.getenv("GMAIL_USER")
GMAIL_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")
EMAIL_TO = os.getenv("EMAIL_TO")
EMAIL_FROM_NAME = os.getenv("EMAIL_FROM_NAME", "Cyberveille Agent")

if not all([GMAIL_USER, GMAIL_PASSWORD, EMAIL_TO]):
    raise ValueError("Missing required environment variables")

# ==============================================================================
# Database Init
# ==============================================================================

def initialize_database():
    init_db()

# ==============================================================================
# CVE pipeline
# ==============================================================================

def retrieve_and_save_cves(hours_back=24):
    cves = fetch_recent_cves(hours_back=hours_back)
    save_cves(cves)
    return cves

# ==============================================================================
# Deduplication
# ==============================================================================

def get_new_cves(min_score=7.0):
    return get_new_high_critical_cves(min_score=min_score)

# ==============================================================================
# Email Alert
# ==============================================================================

def send_email_alert(new_cves, dry_run=False):

    if not new_cves:
        return {"sent": False, "reason": "No new CVEs detected"}

    subject = f"[ALERT] {len(new_cves)} new HIGH/CRITICAL CVEs"

    # Version HTML
    html_body = f"""
    <html>
    <head><style>
        body {{ font-family: Arial, sans-serif; }}
        h2 {{ color: #d32f2f; }}
        .cve {{ border: 1px solid #ccc; padding: 10px; margin: 10px 0; }}
        .score {{ font-weight: bold; }}
        .high {{ color: #f57c00; }}
        .critical {{ color: #d32f2f; }}
    </style></head>
    <body>
        <h2>🚨 Cyber Threat Intelligence Alert</h2>
        <p><strong>{len(new_cves)} new HIGH/CRITICAL CVEs detected.</strong></p>
    """

    for cve in new_cves:
        html_body += f"""
        <div class="cve">
            <strong>{cve['id']}</strong><br>
            Score: <span class="score">{cve['score']}</span><br>
            Severity: <span class="{cve['severity'].lower()}">{cve['severity']}</span><br>
            Description: {cve['description'][:300]}...
        </div>
        """

    html_body += """
        <hr>
        <p>Regards,<br>Cyber Threat Intelligence Agent</p>
    </body>
    </html>
    """

    if dry_run:
        return {"sent": True, "subject": subject, "body": html_body}

    send_email(subject, html_body, html=True)

    return {"sent": True, "count": len(new_cves)}

# ==============================================================================
# Main Agent
# ==============================================================================

def run_agent(hours_back=24, min_score=7.0, dry_run=False):

    initialize_database()

    # Step 1: Fetch CVEs
    recent_cves = retrieve_and_save_cves(hours_back)

    # Step 2: Deduplicate + filter
    new_cves, stats = get_new_cves(min_score=min_score)

    # Step 3: Alerting
    email_result = send_email_alert(new_cves, dry_run=dry_run)

    return {
        "retrieved": len(recent_cves),
        "new_cves": len(new_cves),
        "email_result": email_result,
        "stats": stats
    }

# ==============================================================================
# Entry Point
# ==============================================================================

if __name__ == "__main__":

    result = run_agent(dry_run=False)

    logging.info("Pipeline result:")
    logging.info(result)