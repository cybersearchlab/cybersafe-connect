"""
services/academy/tests/test_academy.py
================================================================================
CyberSafe Connect Academy Microservice
================================================================================

Academy service integration tests.

Tests covered:
    • Health endpoint
    • Module listing
    • Module detail retrieval
    • Quiz authentication
    • Quiz submission
    • Invalid token handling
    • Progress retrieval
    • Response security (hide correct answers)

================================================================================
"""

from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from jose import jwt

from app import app
from config import JWT_ALGORITHM, JWT_SECRET_KEY
from database import Base, SessionLocal, engine
from enums import TargetRole
from models import Choice, Module, Question


# =============================================================================
# JWT Helper
# =============================================================================

def _make_token(
    user_id: int,
    role: str = "citizen",
) -> str:
    """
    Generate valid JWT token for tests.
    """

    payload = {
        "sub": str(user_id),
        "type": "access",
        "email": "test@example.com",
        "role": role,
        "iss": "cybersafe-auth",
        "jti": "test-jti",
        "exp": datetime.utcnow()
        + timedelta(minutes=30),
    }

    return jwt.encode(
        payload,
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM,
    )


# =============================================================================
# Test Fixture
# =============================================================================

@pytest.fixture
def client():
    """
    Create isolated database and test client.
    """

    # Reset database
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()

    # Create test module
    module = Module(
        title="Test Module",
        description="Test description long enough",
        content="Test content long enough for validation",
        target_roles=TargetRole.citizen,
        display_order=1,
    )

    db.add(module)
    db.flush()

    # Create test question
    question = Question(
        module_id=module.id,
        text="Question 1?",
        display_order=1,
    )

    db.add(question)
    db.flush()

    # Create choices
    correct = Choice(
        question_id=question.id,
        text="Correct Answer",
        is_correct=True,
    )

    wrong = Choice(
        question_id=question.id,
        text="Wrong Answer",
        is_correct=False,
    )

    db.add_all([correct, wrong])
    db.commit()

    ctx = {
        "module_id": module.id,
        "question_id": question.id,
        "correct_id": correct.id,
    }

    db.close()

    with TestClient(app) as test_client:
        test_client.test_ctx = ctx
        yield test_client

    # Cleanup
    Base.metadata.drop_all(bind=engine)


# =============================================================================
# Health Tests
# =============================================================================

def test_health(client):
    """
    Health endpoint should return service status.
    """

    response = client.get("/health")

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True
    assert data["service"] == "academy"
    assert data["status"] == "healthy"


# =============================================================================
# Module Tests
# =============================================================================

def test_list_modules(client):
    """
    Module list endpoint should return available modules.
    """

    response = client.get("/academy/modules")

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True
    assert len(data["data"]) >= 1


def test_get_module_detail(client):
    """
    Module detail endpoint should return full module.
    """

    ctx = client.test_ctx

    response = client.get(
        f"/academy/modules/{ctx['module_id']}"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True
    assert data["data"]["id"] == ctx["module_id"]


def test_module_not_found(client):
    """
    Requesting missing module should return 404.
    """

    response = client.get("/academy/modules/99999")

    assert response.status_code == 404


# =============================================================================
# Quiz Authentication Tests
# =============================================================================

def test_quiz_submit_requires_auth(client):
    """
    Quiz submission requires authentication.
    """

    ctx = client.test_ctx

    response = client.post(
        "/academy/quiz/submit",
        json={
            "module_id": ctx["module_id"],
            "answers": {},
        },
    )

    assert response.status_code == 401


def test_invalid_token(client):
    """
    Invalid JWT token should fail.
    """

    response = client.post(
        "/academy/quiz/submit",
        headers={
            "Authorization": "Bearer invalid.token.here"
        },
        json={
            "module_id": 1,
            "answers": {},
        },
    )

    assert response.status_code == 401


# =============================================================================
# Quiz Submission Tests
# =============================================================================

def test_quiz_submit_success(client):
    """
    Valid quiz submission should succeed.
    """

    ctx = client.test_ctx

    token = _make_token(user_id=42)

    response = client.post(
        "/academy/quiz/submit",
        headers={
            "Authorization": f"Bearer {token}"
        },
        json={
            "module_id": ctx["module_id"],
            "answers": {
                str(ctx["question_id"]): ctx["correct_id"]
            },
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True
    assert data["data"]["score"] == 1
    assert data["data"]["total"] == 1
    assert data["data"]["passed"] is True


# =============================================================================
# Progress Tests
# =============================================================================

def test_progress_after_quiz(client):
    """
    Passed quiz should appear in progress endpoint.
    """

    ctx = client.test_ctx

    token = _make_token(user_id=50)

    # Submit quiz first
    client.post(
        "/academy/quiz/submit",
        headers={
            "Authorization": f"Bearer {token}"
        },
        json={
            "module_id": ctx["module_id"],
            "answers": {
                str(ctx["question_id"]): ctx["correct_id"]
            },
        },
    )

    # Check progress
    response = client.get(
        "/academy/progress",
        headers={
            "Authorization": f"Bearer {token}"
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True
    assert ctx["module_id"] in data["data"]["completed"]


# =============================================================================
# Security Tests
# =============================================================================

def test_choices_hide_is_correct(client):
    """
    Public module endpoint must not expose is_correct field.
    """

    ctx = client.test_ctx

    response = client.get(
        f"/academy/modules/{ctx['module_id']}"
    )

    assert response.status_code == 200

    question = response.json()["data"]["questions"][0]

    for choice in question["choices"]:
        assert "is_correct" not in choice