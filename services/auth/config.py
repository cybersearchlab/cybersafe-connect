"""
services/auth/config.py
================================================================================
Configuration — Authentication Microservice (CyberSafe Connect)
================================================================================

Centralizes all configurable values for the service: database connection,
JWT secret, CORS origins, SMTP settings, and rate limits.

Following the scam-checker module's pattern: every value read from an
environment variable has a safe default for local development, never to be
used as-is in production.
================================================================================
"""

import os

from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/users.db")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-secret-change-in-production")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
OTP_EXPIRE_MINUTES = int(os.getenv("OTP_EXPIRE_MINUTES", "15"))

SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
EMAIL_FROM = os.getenv("EMAIL_FROM", SMTP_USER)

ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "ALLOWED_ORIGINS",
        "http://localhost:3000,http://localhost:3001",
    ).split(",")
    if origin.strip()
]

ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
PORT = int(os.getenv("PORT", "8001"))


# =============================================================================
# RATE LIMITING (anti-abuse)
# =============================================================================
# Limits are expressed in slowapi format: "<count>/<period>" where period is
# one of: second, minute, hour, day.
#
# Rationale:
#   - /register      : 3/hour    -> anti account-spam
#   - /login         : 5/minute  -> anti brute force
#   - /verify-email  : 5/minute  -> anti OTP brute force
#   - /refresh       : 10/minute -> anti token abuse
RATE_LIMIT_REGISTER = os.getenv("RATE_LIMIT_REGISTER", "3/hour")
RATE_LIMIT_LOGIN = os.getenv("RATE_LIMIT_LOGIN", "5/minute")
RATE_LIMIT_VERIFY = os.getenv("RATE_LIMIT_VERIFY", "5/minute")
RATE_LIMIT_REFRESH = os.getenv("RATE_LIMIT_REFRESH", "10/minute")
