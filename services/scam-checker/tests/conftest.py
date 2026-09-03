"""
services/scam-checker/tests/conftest.py
================================================================================
Configuration partagée des tests — Module Scam Checker
================================================================================

Isole les tests de la vraie base de données locale (services/scam-checker/
data/scam_checker.db, utilisée pendant le développement manuel) en pointant
DATABASE_URL vers un fichier SQLite temporaire dédié aux tests, créé avant
tout import du service et supprimé à la fin de la session de tests.

Fournit également un client HTTP de test (fixture `client`) et un générateur
de tokens JWT (fixture `make_token`) qui reproduit exactement le format émis
par services/auth/security.py, sans dépendre du service auth lui-même — les
tests du Scam Checker doivent pouvoir tourner seuls.
================================================================================
"""

import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

# La variable d'environnement DOIT être positionnée AVANT le premier import
# d'un module du service : database.py lit DATABASE_URL au moment de
# l'import pour construire le moteur SQLAlchemy global.
TEST_DB_PATH = Path(__file__).parent / "test_scam_checker.db"
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB_PATH}"

# Même principe pour les fichiers de preuve : jamais dans le vrai dossier
# data/evidence utilisé en développement manuel.
TEST_EVIDENCE_DIR = Path(__file__).parent / "test_evidence_files"
os.environ["EVIDENCE_DIR"] = str(TEST_EVIDENCE_DIR)

# Permet `import app`, `import rules`, etc. depuis tests/ sans installer le
# service comme un package — cohérent avec la façon dont le service est
# exécuté en pratique (uvicorn app:app depuis services/scam-checker/).
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from jose import jwt  # noqa: E402

import database  # noqa: E402
import models  # noqa: E402,F401 — l'import déclare les tables sur Base.metadata
from app import app  # noqa: E402
from config import JWT_ALGORITHM, JWT_ISSUER, JWT_SECRET_KEY  # noqa: E402
from limiter import limiter  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _setup_database():
    """Crée les tables une fois pour toute la session de tests, les supprime à la fin."""
    database.Base.metadata.create_all(bind=database.engine)
    yield
    database.engine.dispose()
    if TEST_DB_PATH.exists():
        TEST_DB_PATH.unlink()
    if TEST_EVIDENCE_DIR.exists():
        import shutil
        shutil.rmtree(TEST_EVIDENCE_DIR)


@pytest.fixture(autouse=True)
def _clean_tables():
    """
    Vide toutes les tables après chaque test, pour que l'état d'un test
    (une entrée confirmée, un signalement...) n'influence jamais le suivant.

    Réinitialise aussi le compteur de limitation de débit (limiter.py) :
    slowapi identifie les appels de test par l'adresse IP factice fixe du
    TestClient ("testclient"), qui serait donc partagée par TOUS les tests
    de la session — sans ce reset, les tests exécutés après le 10e appel
    cumulé à /scam/report échoueraient avec une erreur 429 sans rapport avec
    ce qu'ils vérifient réellement.
    """
    yield
    with database.engine.begin() as conn:
        for table in reversed(database.Base.metadata.sorted_tables):
            conn.execute(table.delete())
    limiter.reset()


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def make_token():
    """
    Génère un access token JWT valide, avec la même structure que celle émise
    par services/auth/security.create_access_token — sub, type, iat, exp,
    jti, iss, plus email/role en claims additionnels.
    """
    def _make(user_id: int = 1, email: str = "citizen@test.cm", role: str = "citizen"):
        now = datetime.now(timezone.utc)
        payload = {
            "sub": str(user_id),
            "type": "access",
            "iat": now,
            "exp": now + timedelta(minutes=30),
            "jti": str(uuid.uuid4()),
            "iss": JWT_ISSUER,
            "email": email,
            "role": role,
        }
        return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    return _make


@pytest.fixture
def auth_headers(make_token):
    """Raccourci : en-têtes Authorization prêts à l'emploi pour un citoyen."""
    def _headers(user_id: int = 1, email: str = "citizen@test.cm", role: str = "citizen"):
        return {"Authorization": f"Bearer {make_token(user_id, email, role)}"}

    return _headers
