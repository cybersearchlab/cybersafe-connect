# tests/test_academy.py

from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from jose import jwt

from app import app
from config import JWT_ALGORITHM, JWT_SECRET_KEY
from database import Base, SessionLocal, engine
from enums import TargetRole
from models import Choice, Module, Question


def make_token(
    user_id: int,
    role: str = "citizen",
) -> str:

    payload = {
        "sub": str(user_id),
        "type": "access",
        "email": "test@example.com",
        "role": role,
        "iss": "cybersafe-auth",
        "jti": "test-jti",
        "exp": datetime.utcnow() + timedelta(minutes=30)
    }

    return jwt.encode(
        payload,
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM,
    )


@pytest.fixture
def client():

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()

    module = Module(
        title="Test Module",
        description="Test description long enough",
        content="Test content long enough for validation",
        target_roles=TargetRole.citizen,
        display_order=1,
    )

    db.add(module)
    db.flush()

    question = Question(
        module_id=module.id,
        text="Question 1?",
        display_order=1,
    )

    db.add(question)
    db.flush()

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
        "correct_choice_id": correct.id,
    }

    db.close()

    with TestClient(app) as test_client:
        test_client.test_ctx = ctx
        yield test_client

    Base.metadata.drop_all(bind=engine)


def test_health(client):

    response = client.get("/health")

    assert response.status_code == 200

    data = response.json()

    assert data["service"] == "academy"


def test_list_modules(client):

    response = client.get("/academy/modules")

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True

    assert len(data["data"]) >= 1


def test_quiz_requires_auth(client):

    ctx = client.test_ctx

    response = client.post(
        "/academy/quiz/submit",
        json={
            "module_id": ctx["module_id"],
            "answers": {},
        },
    )

    assert response.status_code == 401


def test_quiz_submit_success(client):

    ctx = client.test_ctx

    token = make_token(42)

    response = client.post(
        "/academy/quiz/submit",
        headers={
            "Authorization": f"Bearer {token}"
        },
        json={
            "module_id": ctx["module_id"],
            "answers": {
                str(ctx["question_id"]): ctx["correct_choice_id"]
            },
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["success"] is True

    assert data["data"]["score"] == 1

    assert data["data"]["passed"] is True


def test_choices_do_not_expose_is_correct(client):

    ctx = client.test_ctx

    response = client.get(
        f"/academy/modules/{ctx['module_id']}"
    )

    assert response.status_code == 200

    question = response.json()["data"]["questions"][0]

    for choice in question["choices"]:
        assert "is_correct" not in choice