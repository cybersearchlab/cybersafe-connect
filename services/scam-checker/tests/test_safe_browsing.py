"""
services/scam-checker/tests/test_safe_browsing.py
================================================================================
Tests de la méthode 5 (optionnelle) — safe_browsing.py
================================================================================

Aucun appel réseau réel dans ces tests : httpx.post est simulé (mock). Le
principe testé le plus important est le "fail open" — toute panne côté API
externe doit se traduire par None, jamais par une exception qui remonterait
jusqu'au citoyen.
================================================================================
"""

from unittest.mock import MagicMock, patch

import httpx

import safe_browsing


def test_returns_none_without_api_key(monkeypatch):
    monkeypatch.setattr(safe_browsing, "SAFE_BROWSING_API_KEY", "")
    with patch("safe_browsing.httpx.post") as mock_post:
        result = safe_browsing.check_url_safe_browsing("http://exemple.com")
    assert result is None
    mock_post.assert_not_called()


def test_returns_true_on_confirmed_match(monkeypatch):
    monkeypatch.setattr(safe_browsing, "SAFE_BROWSING_API_KEY", "test-key")
    response = MagicMock()
    response.raise_for_status = MagicMock()
    response.json.return_value = {"matches": [{"threatType": "SOCIAL_ENGINEERING"}]}
    with patch("safe_browsing.httpx.post", return_value=response):
        result = safe_browsing.check_url_safe_browsing("http://phishing-connu.com")
    assert result is True


def test_returns_false_when_no_match(monkeypatch):
    monkeypatch.setattr(safe_browsing, "SAFE_BROWSING_API_KEY", "test-key")
    response = MagicMock()
    response.raise_for_status = MagicMock()
    response.json.return_value = {}
    with patch("safe_browsing.httpx.post", return_value=response):
        result = safe_browsing.check_url_safe_browsing("https://orange.cm")
    assert result is False


def test_returns_none_on_network_error_fail_open(monkeypatch):
    monkeypatch.setattr(safe_browsing, "SAFE_BROWSING_API_KEY", "test-key")
    with patch("safe_browsing.httpx.post", side_effect=httpx.ConnectTimeout("timeout")):
        result = safe_browsing.check_url_safe_browsing("http://exemple.com")
    assert result is None


def test_returns_none_on_http_error_status_fail_open(monkeypatch):
    monkeypatch.setattr(safe_browsing, "SAFE_BROWSING_API_KEY", "test-key")
    response = MagicMock()
    response.raise_for_status.side_effect = httpx.HTTPStatusError(
        "500", request=MagicMock(), response=MagicMock()
    )
    with patch("safe_browsing.httpx.post", return_value=response):
        result = safe_browsing.check_url_safe_browsing("http://exemple.com")
    assert result is None


def test_returns_none_on_invalid_json_fail_open(monkeypatch):
    monkeypatch.setattr(safe_browsing, "SAFE_BROWSING_API_KEY", "test-key")
    response = MagicMock()
    response.raise_for_status = MagicMock()
    response.json.side_effect = ValueError("not json")
    with patch("safe_browsing.httpx.post", return_value=response):
        result = safe_browsing.check_url_safe_browsing("http://exemple.com")
    assert result is None
