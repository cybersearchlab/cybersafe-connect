"""
services/scam-checker/tests/test_check_endpoint.py
================================================================================
Tests HTTP — GET /health, POST /scam/check
================================================================================
"""


class TestHealth:
    def test_health_returns_healthy(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        body = response.json()
        assert body["success"] is True
        assert body["status"] == "healthy"


class TestScamCheckEndpoint:
    def test_rouge_case(self, client):
        response = client.post(
            "/scam/check",
            json={
                "content": "Félicitations ! Vous avez gagné 500 000 FCFA. "
                           "Contactez le 678901234 pour retirer votre gain."
            },
        )
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["verdict"] == "ROUGE"
        assert data["score"] == 70

    def test_orange_case(self, client):
        response = client.post(
            "/scam/check",
            json={"content": "Bonjour, une offre spéciale vous attend, cliquez ici : bit.ly/xyz123"},
        )
        data = response.json()["data"]
        assert data["verdict"] == "ORANGE"

    def test_vert_case(self, client):
        response = client.post(
            "/scam/check",
            json={
                "content": "Cher client, votre facture ENEO du mois d'août est "
                           "disponible sur eneocameroun.com. Merci de votre confiance."
            },
        )
        data = response.json()["data"]
        assert data["verdict"] == "VERT"
        assert data["score"] == 0
        # Critère d'acceptation : le verdict est toujours accompagné d'au
        # moins un motif explicite, même un message VERT sans indicateur.
        assert len(data["motifs"]) >= 1

    def test_url_input_flagged_correctly(self, client):
        response = client.post("/scam/check", json={"content": "https://orange.cm"})
        assert response.json()["data"]["is_url"] is True

    def test_text_input_flagged_correctly(self, client):
        response = client.post("/scam/check", json={"content": "Bonjour tout le monde"})
        assert response.json()["data"]["is_url"] is False

    def test_empty_content_rejected(self, client):
        response = client.post("/scam/check", json={"content": ""})
        assert response.status_code == 422

    def test_missing_content_field_rejected(self, client):
        response = client.post("/scam/check", json={})
        assert response.status_code == 422

    def test_validation_error_matches_cdc_format(self, client):
        # Critère d'acceptation explicite (CRL-CDC-Module3-2.0 §6) :
        # { success: false, errors: {...} } — pas le format brut FastAPI
        # { detail: [...] }.
        response = client.post("/scam/check", json={})
        body = response.json()
        assert body["success"] is False
        assert isinstance(body["errors"], dict)
        assert "content" in body["errors"]
        assert response.headers["x-error-code"] == "VALIDATION_ERROR"

    def test_response_envelope_format(self, client):
        # Convention {success, message, data} — critère d'acceptation du CDC.
        response = client.post("/scam/check", json={"content": "test"})
        body = response.json()
        assert set(["success", "message", "data"]).issubset(body.keys())

    def test_no_authentication_required(self, client):
        # Critère d'acceptation explicite : un citoyen non connecté doit
        # pouvoir vérifier un texte sans compte.
        response = client.post("/scam/check", json={"content": "test"})
        assert response.status_code == 200


class TestScamCheckLanguage:
    ROUGE_CONTENT = (
        "Félicitations ! Vous avez gagné 500 000 FCFA. "
        "Contactez le 678901234 pour retirer votre gain."
    )

    def test_default_language_is_french(self, client):
        # Aucun champ "lang" fourni — comportement inchangé (français).
        response = client.post("/scam/check", json={"content": self.ROUGE_CONTENT})
        data = response.json()["data"]
        assert "demande d'argent" in data["motifs"]

    def test_explicit_french(self, client):
        response = client.post("/scam/check", json={"content": self.ROUGE_CONTENT, "lang": "fr"})
        data = response.json()["data"]
        assert "demande d'argent" in data["motifs"]
        assert "promesse de gains irréalistes" in data["motifs"]

    def test_english_translates_motifs_and_conseils(self, client):
        response = client.post("/scam/check", json={"content": self.ROUGE_CONTENT, "lang": "en"})
        data = response.json()["data"]
        assert "money request" in data["motifs"]
        assert "unrealistic prize promise" in data["motifs"]
        assert not any("demande d'argent" in m for m in data["motifs"])
        assert any("Do not reply" in c for c in data["conseils"])

    def test_score_and_verdict_unaffected_by_language(self, client):
        # La langue ne change que l'affichage, jamais le calcul du score.
        fr = client.post("/scam/check", json={"content": self.ROUGE_CONTENT, "lang": "fr"}).json()["data"]
        en = client.post("/scam/check", json={"content": self.ROUGE_CONTENT, "lang": "en"}).json()["data"]
        assert fr["score"] == en["score"] == 70
        assert fr["verdict"] == en["verdict"] == "ROUGE"

    def test_english_blacklist_short_circuit_translated(self, client, auth_headers):
        admin = auth_headers(role="admin", email="admin@test.cm")
        client.post(
            "/scam/admin/blacklist",
            json={"type": "phone", "value": "690333222", "reason": "x"},
            headers=admin,
        )
        response = client.post("/scam/check", json={"content": "690333222", "lang": "en"})
        data = response.json()["data"]
        assert data["motifs"] == ["Element confirmed on the blacklist"]

    def test_invalid_language_rejected(self, client):
        response = client.post("/scam/check", json={"content": "test", "lang": "de"})
        assert response.status_code == 422

    def test_new_categories_translated_to_english(self, client):
        # Régression : chaque nouveau motif ajouté au barème (05/09/2026) doit
        # avoir son entrée dans services.MOTIF_TRANSLATIONS_EN, sinon il
        # ressort tel quel en français même quand lang="en" est demandé.
        response = client.post(
            "/scam/check",
            json={
                "content": "Votre ordinateur est infecté, contactez le support Microsoft immédiatement.",
                "lang": "en",
            },
        )
        data = response.json()["data"]
        assert "fake tech support" in data["motifs"]
        assert not any("support technique" in m for m in data["motifs"])
