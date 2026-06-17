"""
email_alert.py
================================================================================
Cyber Threat Intelligence Email Notification Module
================================================================================

This module is responsible for sending automated email alerts generated from
the CVE intelligence pipeline.

It acts as the communication layer of the system, enabling real-time
notification of HIGH and CRITICAL vulnerabilities to security teams.

--------------------------------------------------------------------------------
WORKFLOW
--------------------------------------------------------------------------------

STEP 1 — Environment Loading
    Loads SMTP configuration and credentials from .env file.

STEP 2 — Email Construction
    Builds a structured email message (subject + body).

STEP 3 — SMTP Connection
    Establishes secure TLS connection to SMTP server.

STEP 4 — Authentication
    Authenticates using Gmail App Password.

STEP 5 — Message Transmission
    Sends the constructed email to the configured recipient.

STEP 6 — Error Handling
    Captures and logs SMTP or network failures.

--------------------------------------------------------------------------------
INPUTS
--------------------------------------------------------------------------------

Environment Variables (.env):

    SMTP_SERVER
        SMTP server address (default: smtp.gmail.com)

    SMTP_PORT
        SMTP port (default: 587)

    GMAIL_USER
        Sender email address

    GMAIL_APP_PASSWORD
        Google App Password (NOT normal password)

    EMAIL_TO
        Recipient email address

    EMAIL_FROM_NAME
        Display name for sender

Function Inputs:

    subject : str
        Email subject line

    body : str
        Email content (plain text format)

--------------------------------------------------------------------------------
OUTPUTS
--------------------------------------------------------------------------------

Side Effects:

    - Sends email via SMTP server
    - Prints success or error message in console

Return Value:

    None

--------------------------------------------------------------------------------
SECURITY NOTES
--------------------------------------------------------------------------------

- Requires Gmail App Password (not account password)
- Uses TLS encryption (STARTTLS)
- No credentials are hardcoded in source code
- Environment variables must be securely stored in .env

--------------------------------------------------------------------------------
ROLE IN PIPELINE
--------------------------------------------------------------------------------

This module is part of the alerting layer of the CVE pipeline:

    duplicate.py → detects new CVEs
    pipeline.py   → processes intelligence
    email_alert.py → sends alerts to analysts

It ensures rapid notification of critical vulnerabilities.

--------------------------------------------------------------------------------
USE CASES
--------------------------------------------------------------------------------

- SOC alert notifications
- CVE critical alerting
- Threat intelligence dissemination
- Automated security reporting

================================================================================
"""

# ==============================================================================
# IMPORTS
# ==============================================================================

import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv


# ==============================================================================
# ENVIRONMENT LOADING
# ==============================================================================

load_dotenv()

SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))

GMAIL_USER = os.getenv("GMAIL_USER")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")

EMAIL_TO = os.getenv("EMAIL_TO")
EMAIL_FROM_NAME = os.getenv("EMAIL_FROM_NAME", "CVE Alert System")


# ==============================================================================
# CORE FUNCTION
# ==============================================================================

def send_email(subject: str, body: str, html: bool = False):
    """
    Send an email notification via SMTP.

    Parameters
    ----------
    subject : str
        Email subject line

    body : str
        Email message content

    html : bool
        If True, sends body as HTML; otherwise plain text
    """
    msg = MIMEMultipart("alternative")
    msg["From"] = f"{EMAIL_FROM_NAME} <{GMAIL_USER}>"
    msg["To"] = EMAIL_TO
    msg["Subject"] = subject

    if html:
        msg.attach(MIMEText(body, "html", "utf-8"))
    else:
        msg.attach(MIMEText(body, "plain", "utf-8"))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
        server.send_message(msg)
        server.quit()
        print("📧 Email sent successfully")
    except Exception as e:
        print("❌ Email sending error:", e)