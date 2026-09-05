"""
services/scam-checker/tests/test_report_admin.py
================================================================================
Tests HTTP — méthode 3 (signalement, confirmation/rejet admin) et back-office
================================================================================

Remplace test_report_dispute_admin.py (supprimé) suite à la décision du
27/08/2026 : il n'y a plus de confirmation automatique par seuil de
signalements, ni de contestation citoyenne — seul un administrateur peut
confirmer ou rejeter une entrée.
================================================================================
"""

from datetime import datetime, timedelta, timezone

import database
from models import ScamReport

PHONE = "690112233"


def _set_report_times(entry_id: int, timestamps: list[datetime]) -> None:
    """
    Force les horodatages des signalements d'une entrée, dans l'ordre de
    création — nécessaire pour tester get_report_spread (services.py) sans
    dépendre de délais réels entre deux appels de test.
    """
    with database.SessionLocal() as db:
        reports = (
            db.query(ScamReport)
            .filter(ScamReport.entry_id == entry_id)
            .order_by(ScamReport.id)
            .all()
        )
        for report, ts in zip(reports, timestamps):
            report.created_at = ts
        db.commit()


def _set_report_ips(entry_id: int, ips: list[str]) -> None:
    """
    Force les adresses IP des signalements d'une entrée — le TestClient
    utilisant une adresse factice fixe ("testclient") pour tous les appels,
    ce helper est nécessaire pour tester la diversité des IP (services.
    get_report_spread) sans dépendre d'un vrai réseau multi-origine.
    """
    with database.SessionLocal() as db:
        reports = (
            db.query(ScamReport)
            .filter(ScamReport.entry_id == entry_id)
            .order_by(ScamReport.id)
            .all()
        )
        for report, ip in zip(reports, ips):
            report.ip_address = ip
        db.commit()


class TestReportRequiresAuth:
    def test_report_without_token_rejected(self, client):
        response = client.post("/scam/report", json={"type": "phone", "value": PHONE})
        assert response.status_code == 401

    def test_report_with_invalid_token_rejected(self, client):
        response = client.post(
            "/scam/report",
            json={"type": "phone", "value": PHONE},
            headers={"Authorization": "Bearer not-a-real-token"},
        )
        assert response.status_code == 401


class TestReportNeverAutoConfirms:
    def test_single_report_stays_pending(self, client, auth_headers):
        response = client.post(
            "/scam/report",
            json={"type": "phone", "value": PHONE},
            headers=auth_headers(user_id=1),
        )
        assert response.status_code == 200
        assert response.json()["data"]["status"] == "pending"

    def test_many_reports_still_stay_pending(self, client, auth_headers):
        # Même bien au-delà de l'ancien seuil de 3 — plus aucune confirmation
        # automatique, quel que soit le nombre de signalements reçus.
        for uid in range(1, 6):
            response = client.post(
                "/scam/report",
                json={"type": "phone", "value": PHONE},
                headers=auth_headers(user_id=uid, email=f"user{uid}@test.cm"),
            )
        assert response.json()["data"]["status"] == "pending"
        assert response.json()["data"]["report_count"] == 5

        # Une entrée seulement "pending" ne doit jamais forcer ROUGE.
        check = client.post("/scam/check", json={"content": PHONE})
        assert check.json()["data"]["blacklisted"] is False

    def test_duplicate_report_same_user_rejected(self, client, auth_headers):
        headers = auth_headers(user_id=1)
        client.post("/scam/report", json={"type": "phone", "value": PHONE}, headers=headers)
        response = client.post("/scam/report", json={"type": "phone", "value": PHONE}, headers=headers)
        assert response.status_code == 400

    def test_reporting_already_confirmed_entry_rejected(self, client, auth_headers):
        client.post(
            "/scam/admin/blacklist",
            json={"type": "phone", "value": PHONE, "reason": "Confirmé par avance"},
            headers=auth_headers(role="admin", email="admin@test.cm"),
        )
        response = client.post(
            "/scam/report",
            json={"type": "phone", "value": PHONE},
            headers=auth_headers(user_id=1),
        )
        assert response.status_code == 400


class TestAdminReason:
    # Le motif de la décision admin (confirm/manual_add) est exposé sur
    # chaque entrée — sans exposer l'identité d'un signalant (voir
    # services.get_admin_reasons).
    def test_reason_shown_after_confirm(self, client, auth_headers):
        admin = auth_headers(role="admin", email="admin@test.cm")
        client.post("/scam/report", json={"type": "phone", "value": PHONE}, headers=auth_headers(user_id=1))
        client.post(
            "/scam/admin/confirm",
            json={"type": "phone", "value": PHONE, "reason": "Vérifié auprès de l'opérateur"},
            headers=admin,
        )

        entries = client.get("/scam/admin/entries?status=confirmed", headers=admin).json()["data"]
        entry = next(e for e in entries if e["value"] == PHONE)
        assert entry["admin_reason"] == "Vérifié auprès de l'opérateur"

    def test_reason_shown_after_manual_add(self, client, auth_headers):
        admin = auth_headers(role="admin", email="admin@test.cm")
        client.post(
            "/scam/admin/blacklist",
            json={"type": "phone", "value": PHONE, "reason": "Signalé par la presse"},
            headers=admin,
        )

        entries = client.get("/scam/admin/entries", headers=admin).json()["data"]
        entry = next(e for e in entries if e["value"] == PHONE)
        assert entry["admin_reason"] == "Signalé par la presse"

    def test_reason_null_while_still_pending(self, client, auth_headers):
        admin = auth_headers(role="admin", email="admin@test.cm")
        client.post("/scam/report", json={"type": "phone", "value": PHONE}, headers=auth_headers(user_id=1))

        entries = client.get("/scam/admin/entries?status=pending", headers=admin).json()["data"]
        entry = next(e for e in entries if e["value"] == PHONE)
        assert entry["admin_reason"] is None

    def test_reason_also_exposed_on_public_blacklist(self, client, auth_headers):
        admin = auth_headers(role="admin", email="admin@test.cm")
        client.post(
            "/scam/admin/blacklist",
            json={"type": "phone", "value": PHONE, "reason": "Confirmé par l'équipe CRL"},
            headers=admin,
        )

        entries = client.get("/scam/blacklist", headers=auth_headers(user_id=2, email="u2@test.cm")).json()["data"]
        entry = next(e for e in entries if e["value"] == PHONE)
        assert entry["admin_reason"] == "Confirmé par l'équipe CRL"


class TestAdminConfirm:
    def test_confirm_requires_admin_role(self, client, auth_headers):
        client.post("/scam/report", json={"type": "phone", "value": PHONE}, headers=auth_headers(user_id=1))
        response = client.post(
            "/scam/admin/confirm",
            json={"type": "phone", "value": PHONE, "reason": "x"},
            headers=auth_headers(role="citizen"),
        )
        assert response.status_code == 403

    def test_confirm_on_nonexistent_entry_returns_404(self, client, auth_headers):
        response = client.post(
            "/scam/admin/confirm",
            json={"type": "phone", "value": "699999999", "reason": "x"},
            headers=auth_headers(role="admin", email="admin@test.cm"),
        )
        assert response.status_code == 404

    def test_confirm_pending_entry_succeeds(self, client, auth_headers):
        client.post("/scam/report", json={"type": "phone", "value": PHONE}, headers=auth_headers(user_id=1))

        response = client.post(
            "/scam/admin/confirm",
            json={"type": "phone", "value": PHONE, "reason": "Vérifié auprès de l'opérateur"},
            headers=auth_headers(role="admin", email="admin@test.cm"),
        )
        assert response.status_code == 200

        check = client.post("/scam/check", json={"content": PHONE})
        data = check.json()["data"]
        assert data["verdict"] == "ROUGE"
        assert data["score"] == 100
        assert data["blacklisted"] is True

    def test_confirm_already_confirmed_entry_rejected(self, client, auth_headers):
        admin = auth_headers(role="admin", email="admin@test.cm")
        client.post("/scam/report", json={"type": "phone", "value": PHONE}, headers=auth_headers(user_id=1))
        client.post("/scam/admin/confirm", json={"type": "phone", "value": PHONE, "reason": "x"}, headers=admin)

        response = client.post(
            "/scam/admin/confirm", json={"type": "phone", "value": PHONE, "reason": "x"}, headers=admin
        )
        assert response.status_code == 404


class TestAdminReject:
    def test_reject_requires_admin_role(self, client, auth_headers):
        client.post("/scam/report", json={"type": "phone", "value": PHONE}, headers=auth_headers(user_id=1))
        response = client.post(
            "/scam/admin/reject",
            json={"type": "phone", "value": PHONE, "reason": "x"},
            headers=auth_headers(role="citizen"),
        )
        assert response.status_code == 403

    def test_reject_nonexistent_entry_returns_404(self, client, auth_headers):
        response = client.post(
            "/scam/admin/reject",
            json={"type": "phone", "value": "699999999", "reason": "x"},
            headers=auth_headers(role="admin", email="admin@test.cm"),
        )
        assert response.status_code == 404

    def test_reject_pending_entry_removes_it(self, client, auth_headers):
        client.post("/scam/report", json={"type": "phone", "value": PHONE}, headers=auth_headers(user_id=1))

        response = client.post(
            "/scam/admin/reject",
            json={"type": "phone", "value": PHONE, "reason": "Signalement non fondé"},
            headers=auth_headers(role="admin", email="admin@test.cm"),
        )
        assert response.status_code == 200

        # Une entrée rejetée disparaît entièrement — un nouveau signalement
        # doit pouvoir repartir de zéro (report_count reparti de 1).
        again = client.post(
            "/scam/report",
            json={"type": "phone", "value": PHONE},
            headers=auth_headers(user_id=2, email="user2@test.cm"),
        )
        assert again.json()["data"]["report_count"] == 1

    def test_reject_can_remove_a_confirmed_entry(self, client, auth_headers):
        # Remplace l'ancien mécanisme de contestation : un admin qui découvre
        # après coup qu'une confirmation était une erreur peut la retirer
        # directement, sans étape de contestation intermédiaire.
        admin = auth_headers(role="admin", email="admin@test.cm")
        client.post(
            "/scam/admin/blacklist",
            json={"type": "phone", "value": PHONE, "reason": "Signalé par erreur"},
            headers=admin,
        )
        check_before = client.post("/scam/check", json={"content": PHONE})
        assert check_before.json()["data"]["blacklisted"] is True

        response = client.post(
            "/scam/admin/reject",
            json={"type": "phone", "value": PHONE, "reason": "Numéro réattribué, confirmé à tort"},
            headers=admin,
        )
        assert response.status_code == 200

        check_after = client.post("/scam/check", json={"content": PHONE})
        assert check_after.json()["data"]["blacklisted"] is False


class TestAdminManualAddAndWhitelist:
    def test_admin_endpoints_reject_citizen_role(self, client, auth_headers):
        headers = auth_headers(role="citizen")
        for path, payload in [
            ("/scam/admin/blacklist", {"type": "phone", "value": PHONE, "reason": "x"}),
            ("/scam/admin/whitelist", {"type": "domain", "value": "orange.cm", "brand_name": "Orange"}),
        ]:
            response = client.post(path, json=payload, headers=headers)
            assert response.status_code == 403, f"{path} devrait rejeter un rôle citizen"

        response = client.get("/scam/admin/audit", headers=headers)
        assert response.status_code == 403

    def test_admin_manual_add_confirms_immediately(self, client, auth_headers):
        response = client.post(
            "/scam/admin/blacklist",
            json={"type": "phone", "value": PHONE, "reason": "Signalé par la presse"},
            headers=auth_headers(role="admin", email="admin@test.cm"),
        )
        assert response.status_code == 200

        check = client.post("/scam/check", json={"content": PHONE})
        assert check.json()["data"]["blacklisted"] is True

    def test_admin_whitelist_neutralizes_official_domain_only(self, client, auth_headers):
        admin_headers = auth_headers(role="admin", email="admin@test.cm")

        before = client.post("/scam/check", json={"content": "http://compte.securite.orange.faux.com"})
        assert any("identité usurpée" in m for m in before.json()["data"]["motifs"])

        client.post(
            "/scam/admin/whitelist",
            json={"type": "domain", "value": "orange.cm", "brand_name": "Orange"},
            headers=admin_headers,
        )

        legit = client.post("/scam/check", json={"content": "https://orange.cm"})
        assert legit.json()["data"]["whitelisted"] is True
        assert legit.json()["data"]["verdict"] == "VERT"

        still_fake = client.post("/scam/check", json={"content": "http://compte.securite.orange.faux.com"})
        assert any("identité usurpée" in m for m in still_fake.json()["data"]["motifs"])


class TestAdminEntriesListing:
    def test_requires_admin(self, client, auth_headers):
        response = client.get("/scam/admin/entries", headers=auth_headers(role="citizen"))
        assert response.status_code == 403

    def test_filter_by_pending_status(self, client, auth_headers):
        client.post("/scam/report", json={"type": "phone", "value": PHONE}, headers=auth_headers(user_id=1))
        client.post(
            "/scam/admin/blacklist",
            json={"type": "phone", "value": "699000111", "reason": "x"},
            headers=auth_headers(role="admin", email="admin@test.cm"),
        )

        response = client.get(
            "/scam/admin/entries?status=pending",
            headers=auth_headers(role="admin", email="admin@test.cm"),
        )
        values = [e["value"] for e in response.json()["data"]]
        assert PHONE in values
        assert "699000111" not in values

    def test_filter_by_type(self, client, auth_headers):
        admin = auth_headers(role="admin", email="admin@test.cm")
        client.post("/scam/admin/blacklist", json={"type": "phone", "value": PHONE, "reason": "x"}, headers=admin)
        client.post(
            "/scam/admin/blacklist",
            json={"type": "domain", "value": "faux-site.cm", "reason": "x"},
            headers=admin,
        )

        response = client.get("/scam/admin/entries?type=domain", headers=admin)
        values = [e["value"] for e in response.json()["data"]]
        assert "faux-site.cm" in values
        assert PHONE not in values

    def test_filter_by_since_date_excludes_older_entries(self, client, auth_headers):
        admin = auth_headers(role="admin", email="admin@test.cm")
        client.post("/scam/admin/blacklist", json={"type": "phone", "value": PHONE, "reason": "x"}, headers=admin)

        far_future = "2099-01-01T00:00:00"
        response = client.get(f"/scam/admin/entries?since={far_future}", headers=admin)
        assert response.json()["data"] == []

    def test_sort_by_reports_orders_most_reported_first(self, client, auth_headers):
        admin = auth_headers(role="admin", email="admin@test.cm")
        # PHONE reçoit 1 signalement, l'autre en reçoit 3.
        client.post("/scam/report", json={"type": "phone", "value": PHONE}, headers=auth_headers(user_id=1))
        heavily_reported = "699000222"
        for uid in range(1, 4):
            client.post(
                "/scam/report",
                json={"type": "phone", "value": heavily_reported},
                headers=auth_headers(user_id=uid, email=f"u{uid}@test.cm"),
            )

        response = client.get("/scam/admin/entries?sort=reports", headers=admin)
        values = [e["value"] for e in response.json()["data"]]
        assert values.index(heavily_reported) < values.index(PHONE)


class TestReportSpreadDiversity:
    # Priorisation par étalement temporel (benchmark 28/08/2026, inspiré de
    # PhishTank/Community Notes) — un signal d'aide à la décision affiché
    # dans le back-office, jamais une confirmation/un rejet automatique.
    def _report(self, client, auth_headers, uid):
        client.post(
            "/scam/report",
            json={"type": "phone", "value": PHONE},
            headers=auth_headers(user_id=uid, email=f"u{uid}@test.cm"),
        )

    def test_burst_of_reports_flagged_as_coordinated(self, client, auth_headers):
        admin = auth_headers(role="admin", email="admin@test.cm")
        for uid in range(1, 4):
            self._report(client, auth_headers, uid)

        # Les 3 signalements arrivent tous à quelques millisecondes d'écart
        # dans le test — un cas limite de rafale, laissé tel quel par défaut.
        response = client.get("/scam/admin/entries", headers=admin)
        entry = response.json()["data"][0]
        assert entry["coordinated_pattern_suspected"] is True

    def test_spread_out_reports_not_flagged_as_coordinated(self, client, auth_headers):
        admin = auth_headers(role="admin", email="admin@test.cm")
        for uid in range(1, 4):
            self._report(client, auth_headers, uid)

        entry_id = client.get("/scam/admin/entries", headers=admin).json()["data"][0]["id"]
        base = datetime.now(timezone.utc)
        _set_report_times(entry_id, [base, base + timedelta(hours=6), base + timedelta(hours=30)])

        response = client.get("/scam/admin/entries", headers=admin)
        entry = next(e for e in response.json()["data"] if e["id"] == entry_id)
        assert entry["coordinated_pattern_suspected"] is False
        assert entry["report_spread_minutes"] > 1000

    def test_single_report_never_flagged(self, client, auth_headers):
        admin = auth_headers(role="admin", email="admin@test.cm")
        self._report(client, auth_headers, 1)

        response = client.get("/scam/admin/entries", headers=admin)
        entry = response.json()["data"][0]
        assert entry["coordinated_pattern_suspected"] is False
        assert entry["report_spread_minutes"] == 0.0

    def test_coordinated_flag_never_blocks_confirmation(self, client, auth_headers):
        # Le signal est purement informatif — un admin reste libre de
        # confirmer malgré une rafale suspecte (son jugement prime).
        admin = auth_headers(role="admin", email="admin@test.cm")
        for uid in range(1, 4):
            self._report(client, auth_headers, uid)

        response = client.post(
            "/scam/admin/confirm",
            json={"type": "phone", "value": PHONE, "reason": "Vérifié malgré la rafale"},
            headers=admin,
        )
        assert response.status_code == 200


class TestReportIpDiversity:
    # Pondération anti-brigading (benchmark 05/09/2026, inspiré de
    # Truecaller) — un signal complémentaire à l'étalement temporel : un même
    # acteur signalant depuis plusieurs comptes mais une seule connexion,
    # même étalé dans le temps, reste invisible à l'analyse temporelle seule.
    def _report(self, client, auth_headers, uid):
        client.post(
            "/scam/report",
            json={"type": "phone", "value": PHONE},
            headers=auth_headers(user_id=uid, email=f"u{uid}@test.cm"),
        )

    def test_reports_from_same_ip_flagged_low_diversity(self, client, auth_headers):
        admin = auth_headers(role="admin", email="admin@test.cm")
        for uid in range(1, 4):
            self._report(client, auth_headers, uid)

        entry_id = client.get("/scam/admin/entries", headers=admin).json()["data"][0]["id"]
        _set_report_ips(entry_id, ["41.202.1.10", "41.202.1.10", "41.202.1.10"])

        response = client.get("/scam/admin/entries", headers=admin)
        entry = next(e for e in response.json()["data"] if e["id"] == entry_id)
        assert entry["distinct_ip_count"] == 1
        assert entry["low_diversity_suspected"] is True

    def test_reports_from_distinct_ips_not_flagged(self, client, auth_headers):
        admin = auth_headers(role="admin", email="admin@test.cm")
        for uid in range(1, 4):
            self._report(client, auth_headers, uid)

        entry_id = client.get("/scam/admin/entries", headers=admin).json()["data"][0]["id"]
        _set_report_ips(entry_id, ["41.202.1.10", "196.24.3.5", "102.65.10.20"])

        response = client.get("/scam/admin/entries", headers=admin)
        entry = next(e for e in response.json()["data"] if e["id"] == entry_id)
        assert entry["distinct_ip_count"] == 3
        assert entry["low_diversity_suspected"] is False

    def test_unknown_ip_not_treated_as_suspicious(self, client, auth_headers):
        # Signalements sans IP connue (ip_address=None — ex. données
        # antérieures à cette colonne) — ne doit jamais être traité comme
        # "diversité faible" faute de donnée, seul un décompte confirmé à 1
        # déclenche ce signal (voir services.get_report_spread).
        admin = auth_headers(role="admin", email="admin@test.cm")
        for uid in range(1, 4):
            self._report(client, auth_headers, uid)

        entry_id = client.get("/scam/admin/entries", headers=admin).json()["data"][0]["id"]
        _set_report_ips(entry_id, [None, None, None])

        response = client.get("/scam/admin/entries", headers=admin)
        entry = next(e for e in response.json()["data"] if e["id"] == entry_id)
        assert entry["distinct_ip_count"] == 0
        assert entry["low_diversity_suspected"] is False

    def test_low_diversity_flag_never_blocks_confirmation(self, client, auth_headers):
        admin = auth_headers(role="admin", email="admin@test.cm")
        for uid in range(1, 4):
            self._report(client, auth_headers, uid)
        entry_id = client.get("/scam/admin/entries", headers=admin).json()["data"][0]["id"]
        _set_report_ips(entry_id, ["41.202.1.10", "41.202.1.10", "41.202.1.10"])

        response = client.post(
            "/scam/admin/confirm",
            json={"type": "phone", "value": PHONE, "reason": "Vérifié malgré la diversité faible"},
            headers=admin,
        )
        assert response.status_code == 200


class TestAuditLog:
    def test_audit_log_records_report_and_confirm(self, client, auth_headers):
        client.post("/scam/report", json={"type": "phone", "value": PHONE}, headers=auth_headers(user_id=1))
        client.post(
            "/scam/admin/confirm",
            json={"type": "phone", "value": PHONE, "reason": "Vérifié"},
            headers=auth_headers(role="admin", email="admin@test.cm"),
        )

        response = client.get("/scam/admin/audit", headers=auth_headers(role="admin", email="admin@test.cm"))
        assert response.status_code == 200
        actions = [entry["action"] for entry in response.json()["data"]]
        assert "report" in actions
        assert "confirm" in actions
        # "system" n'apparaît plus jamais comme acteur — confirmation
        # toujours attribuée à un administrateur identifié.
        actors = [entry["actor"] for entry in response.json()["data"]]
        assert "system" not in actors

    def test_audit_log_requires_admin(self, client, auth_headers):
        response = client.get("/scam/admin/audit", headers=auth_headers(role="citizen"))
        assert response.status_code == 403
