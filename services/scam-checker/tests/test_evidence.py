"""
services/scam-checker/tests/test_evidence.py
================================================================================
Tests des preuves de signalement (captures d'écran, documents)
================================================================================
"""

import io

PHONE = "690555444"

PNG_1X1 = bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000001000000010802000000907753"
    "de0000000c4944415478da6360606060000000050001a5f645400000000049454e44ae426082"
)


def _create_report(client, auth_headers, phone=PHONE):
    response = client.post(
        "/scam/report",
        json={"type": "phone", "value": phone, "description": "Reçu un appel demandant mon code."},
        headers=auth_headers(user_id=1),
    )
    return response.json()["data"]["report_id"]


class TestModeOperatoire:
    def test_description_stored_on_report(self, client, auth_headers):
        _create_report(client, auth_headers)
        # Vérifié indirectement via la liste publique des entrées confirmées
        # après confirmation — voir TestBlacklistListing.

    def test_description_accumulates_across_reports(self, client, auth_headers):
        client.post(
            "/scam/report",
            json={"type": "phone", "value": PHONE, "description": "Premier témoignage."},
            headers=auth_headers(user_id=1, email="u1@test.cm"),
        )
        client.post(
            "/scam/report",
            json={"type": "phone", "value": PHONE, "description": "Deuxième témoignage."},
            headers=auth_headers(user_id=2, email="u2@test.cm"),
        )
        client.post(
            "/scam/report",
            json={"type": "phone", "value": PHONE, "description": "Troisième témoignage."},
            headers=auth_headers(user_id=3, email="u3@test.cm"),
        )

        # Aucune confirmation automatique : un administrateur doit valider
        # avant que l'entrée n'apparaisse dans la liste publique.
        client.post(
            "/scam/admin/confirm",
            json={"type": "phone", "value": PHONE, "reason": "Trois témoignages concordants"},
            headers=auth_headers(role="admin", email="admin@test.cm"),
        )

        response = client.get("/scam/blacklist", headers=auth_headers(user_id=4, email="u4@test.cm"))
        entries = response.json()["data"]
        entry = next(e for e in entries if e["value"] == PHONE)
        assert "Premier témoignage" in entry["description"]
        assert "Deuxième témoignage" in entry["description"]
        assert "Troisième témoignage" in entry["description"]

    def test_report_without_description_still_works(self, client, auth_headers):
        response = client.post(
            "/scam/report",
            json={"type": "phone", "value": "690111222"},
            headers=auth_headers(user_id=1),
        )
        assert response.status_code == 200


class TestBlacklistListing:
    def test_requires_authentication(self, client):
        response = client.get("/scam/blacklist")
        assert response.status_code == 401

    def test_available_to_any_authenticated_user_not_just_admin(self, client, auth_headers):
        response = client.get("/scam/blacklist", headers=auth_headers(role="citizen"))
        assert response.status_code == 200

    def test_only_confirmed_entries_are_listed(self, client, auth_headers):
        # Une seule signalement -> reste "pending", ne doit PAS apparaître.
        client.post(
            "/scam/report",
            json={"type": "phone", "value": "690999888"},
            headers=auth_headers(user_id=1),
        )
        response = client.get("/scam/blacklist", headers=auth_headers(user_id=2, email="u2@test.cm"))
        values = [e["value"] for e in response.json()["data"]]
        assert "690999888" not in values


class TestEvidenceUpload:
    def test_upload_requires_auth(self, client):
        response = client.post(
            "/scam/report/1/evidence",
            files={"file": ("preuve.png", PNG_1X1, "image/png")},
        )
        assert response.status_code == 401

    def test_upload_to_own_report_succeeds(self, client, auth_headers):
        report_id = _create_report(client, auth_headers)
        response = client.post(
            f"/scam/report/{report_id}/evidence",
            files={"file": ("capture.png", PNG_1X1, "image/png")},
            headers=auth_headers(user_id=1),
        )
        assert response.status_code == 200
        assert response.json()["data"]["filename"] == "capture.png"

    def test_upload_to_someone_elses_report_rejected(self, client, auth_headers):
        report_id = _create_report(client, auth_headers)
        response = client.post(
            f"/scam/report/{report_id}/evidence",
            files={"file": ("capture.png", PNG_1X1, "image/png")},
            headers=auth_headers(user_id=2, email="autre@test.cm"),
        )
        assert response.status_code == 403

    def test_upload_rejects_disallowed_content_type(self, client, auth_headers):
        report_id = _create_report(client, auth_headers)
        response = client.post(
            f"/scam/report/{report_id}/evidence",
            files={"file": ("script.exe", b"MZ...", "application/x-msdownload")},
            headers=auth_headers(user_id=1),
        )
        assert response.status_code == 400

    def test_upload_to_nonexistent_report_returns_404(self, client, auth_headers):
        response = client.post(
            "/scam/report/999999/evidence",
            files={"file": ("capture.png", PNG_1X1, "image/png")},
            headers=auth_headers(user_id=1),
        )
        assert response.status_code == 404

    def test_list_own_evidence(self, client, auth_headers):
        report_id = _create_report(client, auth_headers)
        client.post(
            f"/scam/report/{report_id}/evidence",
            files={"file": ("capture.png", PNG_1X1, "image/png")},
            headers=auth_headers(user_id=1),
        )
        response = client.get(f"/scam/report/{report_id}/evidence", headers=auth_headers(user_id=1))
        assert response.status_code == 200
        assert len(response.json()["data"]) == 1

    def test_admin_can_list_entry_evidence(self, client, auth_headers):
        report_id = _create_report(client, auth_headers)
        client.post(
            f"/scam/report/{report_id}/evidence",
            files={"file": ("capture.png", PNG_1X1, "image/png")},
            headers=auth_headers(user_id=1),
        )
        response = client.get(
            "/scam/admin/entries/1/evidence", headers=auth_headers(role="admin", email="admin@test.cm")
        )
        assert response.status_code == 200

    def test_download_by_owner_succeeds(self, client, auth_headers):
        report_id = _create_report(client, auth_headers)
        upload = client.post(
            f"/scam/report/{report_id}/evidence",
            files={"file": ("capture.png", PNG_1X1, "image/png")},
            headers=auth_headers(user_id=1),
        )
        evidence_id = upload.json()["data"]["id"]
        response = client.get(f"/scam/evidence/{evidence_id}/download", headers=auth_headers(user_id=1))
        assert response.status_code == 200
        assert response.content == PNG_1X1

    def test_download_by_stranger_rejected(self, client, auth_headers):
        report_id = _create_report(client, auth_headers)
        upload = client.post(
            f"/scam/report/{report_id}/evidence",
            files={"file": ("capture.png", PNG_1X1, "image/png")},
            headers=auth_headers(user_id=1),
        )
        evidence_id = upload.json()["data"]["id"]
        response = client.get(
            f"/scam/evidence/{evidence_id}/download",
            headers=auth_headers(user_id=2, email="autre@test.cm"),
        )
        assert response.status_code == 403

    def test_download_by_admin_succeeds(self, client, auth_headers):
        report_id = _create_report(client, auth_headers)
        upload = client.post(
            f"/scam/report/{report_id}/evidence",
            files={"file": ("capture.png", PNG_1X1, "image/png")},
            headers=auth_headers(user_id=1),
        )
        evidence_id = upload.json()["data"]["id"]
        response = client.get(
            f"/scam/evidence/{evidence_id}/download",
            headers=auth_headers(role="admin", email="admin@test.cm"),
        )
        assert response.status_code == 200
