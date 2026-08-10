"""
services/academy/enums.py
================================================================================
CyberSafe Connect Academy Microservice
================================================================================

Application enumerations.

Responsibilities:
    • User role targeting
    • Quiz status definitions
    • Internal service constants
    • Academy access control values

This file MUST NOT contain:
    • Business logic
    • Authentication logic
    • Database models

================================================================================
"""

from enum import Enum


# =============================================================================
# Module Access Roles
# =============================================================================

class TargetRole(str, Enum):
    """
    Defines which user category can access a learning module.

    Values:
        • citizen → public individual users
        • company → organization/company users
        • both → accessible by both groups
    """

    citizen = "citizen"
    company = "company"
    both = "both"


# =============================================================================
# Quiz Completion Status
# =============================================================================

class QuizStatus(str, Enum):
    """
    Represents quiz evaluation status.

    Values:
        • passed → user passed the quiz
        • failed → user did not pass
    """

    passed = "passed"
    failed = "failed"


# =============================================================================
# Public exports
# =============================================================================

__all__ = [
    "TargetRole",
    "QuizStatus",
]