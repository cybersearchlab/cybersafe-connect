import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from config import (
    EMAIL_FROM,
    ENVIRONMENT,
    SMTP_HOST,
    SMTP_PASSWORD,
    SMTP_PORT,
    SMTP_USER,
)

logger = logging.getLogger(__name__)


def _smtp_configured() -> bool:
    return bool(SMTP_HOST and SMTP_USER and SMTP_PASSWORD and EMAIL_FROM)


def send_verification_email(to_email: str, fullname: str, code: str) -> bool:
    subject = "CyberSafe Connect — Vérification de votre compte"
    html_body = f"""
    <html>
    <body style="font-family: Arial, sans-serif; color: #333;">
        <h2>Bienvenue sur CyberSafe Connect</h2>
        <p>Bonjour <strong>{fullname}</strong>,</p>
        <p>Utilisez ce code pour vérifier votre compte :</p>
        <p style="font-size: 28px; font-weight: bold; letter-spacing: 4px;">{code}</p>
        <p>Ce code expire dans quelques minutes.</p>
        <p>— L'équipe CyberSafe Connect</p>
    </body>
    </html>
    """

    if not _smtp_configured():
        if ENVIRONMENT == "development":
            logger.info(
                "SMTP not configured — verification code for %s: %s",
                to_email,
                code,
            )
        return False

    try:
        message = MIMEMultipart("alternative")
        message["Subject"] = subject
        message["From"] = EMAIL_FROM
        message["To"] = to_email
        message.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(EMAIL_FROM, to_email, message.as_string())

        return True
    except Exception:
        logger.exception("Failed to send verification email to %s", to_email)
        return False
