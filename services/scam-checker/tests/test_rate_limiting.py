"""
services/scam-checker/tests/test_rate_limiting.py
================================================================================
Tests de la limitation de débit (anti-abus) — config.RATE_LIMIT_CHECK / RATE_LIMIT_REPORT
================================================================================

Contrairement aux autres fichiers de tests, ceux-ci ne réinitialisent PAS le
limiteur après chaque test (voir conftest.py, fixture _clean_tables) — c'est
précisément l'accumulation de requêtes qu'on veut observer ici. Le compteur
est remis à zéro manuellement au début de chaque test pour rester isolé du
reste de la suite.
================================================================================
"""

from limiter import limiter


def _reset():
    limiter.reset()


class TestCheckRateLimit:
    def test_requests_under_limit_all_succeed(self, client):
        _reset()
        for _ in range(30):
            response = client.post("/scam/check", json={"content": "test"})
            assert response.status_code == 200

    def test_request_over_limit_returns_429(self, client):
        _reset()
        for _ in range(30):
            client.post("/scam/check", json={"content": "test"})

        response = client.post("/scam/check", json={"content": "test"})
        assert response.status_code == 429
        body = response.json()
        assert body["success"] is False
        assert body["code"] == "RATE_LIMITED"


class TestReportRateLimit:
    def test_request_over_limit_returns_429(self, client, auth_headers):
        _reset()
        headers = auth_headers(user_id=1)
        for i in range(10):
            client.post(
                "/scam/report",
                json={"type": "phone", "value": f"69000000{i}"},
                headers=headers,
            )

        response = client.post(
            "/scam/report",
            json={"type": "phone", "value": "690000099"},
            headers=headers,
        )
        assert response.status_code == 429
