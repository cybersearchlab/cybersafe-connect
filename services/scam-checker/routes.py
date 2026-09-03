"""
services/scam-checker/routes.py
================================================================================
Endpoints HTTP — Module Scam Checker (CyberSafe Connect)
================================================================================

Ce module définit tous les endpoints exposés par le microservice. Sa
responsabilité est strictement limitée à :

    • Recevoir la requête HTTP
    • Valider le corps de la requête via les schémas Pydantic (schemas.py)
    • Injecter les dépendances nécessaires (base de données, utilisateur
      courant, rôle admin — dependencies.py)
    • Déléguer toute la logique métier à services.py
    • Retourner une réponse standardisée

--------------------------------------------------------------------------------
ARCHITECTURE ROLE
--------------------------------------------------------------------------------
Ce module ne contient AUCUNE logique métier — sur le modèle exact de
services/auth/routes.py. Aucun accès direct aux modèles ORM, aucun calcul de
score : tout est délégué à services.py, ce qui permet de tester la logique
métier indépendamment du transport HTTP.

--------------------------------------------------------------------------------
ENDPOINTS DISPONIBLES
--------------------------------------------------------------------------------
Les 5 premiers sont listés explicitement dans CRL-CDC-Module3-2.0 §7 ; les
suivants (whitelist, confirm, reject, entries, evidence...) sont des ajouts
nécessaires pour que le back-office administrateur décrit en §3.6 fonctionne
réellement — voir CRL - CDC - Module 3 - 2.0.docx §13 pour cette remarque.

Décision du 27/08/2026 : il n'existe plus de contestation citoyenne — seul
un administrateur confirme ou rejette une entrée (voir enums.EntryStatus et
services.admin_confirm_entry / admin_reject_entry).

    POST    /scam/check              Vérifier un texte ou une URL (auth optionnelle)
    POST    /scam/report              Signaler une entrée, mode opératoire optionnel (auth requise)
    GET     /scam/blacklist          Liste des entrées confirmées (tout compte authentifié)
    POST    /scam/admin/blacklist    Ajout manuel en liste noire, déjà confirmée (admin)
    POST    /scam/admin/whitelist    Ajout manuel en liste blanche (admin)
    POST    /scam/admin/confirm      Confirme une entrée "pending" (admin)
    POST    /scam/admin/reject      Rejette/retire une entrée, tout statut (admin)
    GET     /scam/admin/entries      Vue d'ensemble de toutes les entrées (admin)
    GET     /scam/admin/audit          Consulter le journal d'audit (admin)

--------------------------------------------------------------------------------
LIMITATION DE DEBIT
--------------------------------------------------------------------------------
/scam/check et l'endpoint d'écriture citoyenne /scam/report portent un
décorateur @limiter.limit(...) — les endpoints admin n'en ont pas : ils sont
déjà protégés par require_admin, un public beaucoup plus restreint et de
confiance.
================================================================================
"""

from datetime import datetime

from fastapi import APIRouter, Depends, File, Request, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from config import MAX_TEXT_LENGTH, RATE_LIMIT_CHECK, RATE_LIMIT_REPORT
from dependencies import CurrentUser, get_current_user, get_db, require_admin
from limiter import limiter
from schemas import (
    AdminBlacklistRequest,
    AdminConfirmRequest,
    AdminRejectRequest,
    AdminWhitelistRequest,
    ScamCheckRequest,
    ScamReportRequest,
)
from enums import EntryStatus, EntryType
from services import (
    admin_add_blacklist_entry,
    admin_add_whitelist_entry,
    admin_confirm_entry,
    admin_reject_entry,
    check_scam,
    get_admin_reasons,
    get_all_entries,
    get_audit_log,
    get_confirmed_entries,
    get_evidence_file,
    get_report_spread,
    list_evidence_for_entry,
    list_evidence_for_report,
    report_entry,
    save_evidence,
)

router = APIRouter(prefix="/scam", tags=["Scam Checker"])


# =============================================================================
# VERIFICATION D'UN TEXTE OU D'UNE URL
# =============================================================================
@router.post("/check")
@limiter.limit(RATE_LIMIT_CHECK)
def check(request: Request, payload: ScamCheckRequest, db: Session = Depends(get_db)):
    """
    Endpoint principal du module — accessible sans compte utilisateur
    (critère d'acceptation). `request: Request` est requis par slowapi pour
    identifier l'IP appelante, même s'il n'est pas utilisé directement ici.
    """
    content = payload.content[:MAX_TEXT_LENGTH]
    result = check_scam(content, db, payload.lang.value)
    return {
        "success": True,
        "message": "Analyse effectuée",
        "data": result,
    }


# =============================================================================
# SIGNALEMENT COMMUNAUTAIRE
# =============================================================================
@router.post("/report")
@limiter.limit(RATE_LIMIT_REPORT)
def report(
    request: Request,
    payload: ScamReportRequest,
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """Nécessite un compte connecté — get_current_user lève une 401 sinon."""
    return report_entry(
        db, payload.type, payload.value, current_user.user_id, current_user.email,
        payload.description,
    )


# =============================================================================
# BACK-OFFICE ADMIN
# =============================================================================
@router.post("/admin/blacklist")
def admin_add_blacklist(
    payload: AdminBlacklistRequest,
    db: Session = Depends(get_db),
    admin: CurrentUser = Depends(require_admin),
):
    """require_admin vérifie à la fois l'authentification ET le rôle admin."""
    return admin_add_blacklist_entry(
        db, payload.type, payload.value, payload.reason, admin.email, payload.description,
    )


@router.get("/blacklist")
def list_confirmed(
    limit: int = 200,
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Liste des entrées confirmées — ouverte à tout compte authentifié (pas
    seulement aux administrateurs), pour que la communauté puisse consulter
    ce qui a déjà été signalé et confirmé, avec le mode opératoire rapporté.
    """
    entries = get_confirmed_entries(db, limit)
    reasons = get_admin_reasons(db, entries)
    return {
        "success": True,
        "message": "Liste noire confirmée",
        "data": [
            {
                "id": e.id,
                "type": e.type.value,
                "value": e.value,
                "report_count": e.report_count,
                "description": e.description,
                "admin_reason": reasons.get((e.type, e.value)),
                "updated_at": e.updated_at.isoformat(),
            }
            for e in entries
        ],
    }


@router.get("/admin/entries")
def admin_list_entries(
    status: EntryStatus | None = None,
    type: EntryType | None = None,
    since: datetime | None = None,
    sort: str = "recent",
    limit: int = 200,
    db: Session = Depends(get_db),
    admin: CurrentUser = Depends(require_admin),
):
    """
    Vue d'ensemble administrateur de toutes les entrées — filtrable par
    statut, type et date (ex. ?status=pending&type=phone&since=2026-08-01),
    critère d'acceptation CRL-CDC-Module3-2.0 §3.5. Contrairement à
    GET /scam/blacklist, montre aussi "pending", pas seulement "confirmed".

    sort=reports trie par nombre de signalements décroissant plutôt que par
    date de modification — priorise la revue des entrées les plus
    corroborées. Chaque entrée porte aussi report_spread_minutes et
    coordinated_pattern_suspected (voir services.get_report_spread) : un
    signal d'aide à la décision, jamais une confirmation ou un rejet
    automatique.
    """
    entries = get_all_entries(db, status, type, since, sort, limit)
    spread = get_report_spread(db, [e.id for e in entries])
    reasons = get_admin_reasons(db, entries)
    return {
        "success": True,
        "message": "Entrées de la liste noire",
        "data": [
            {
                "id": e.id,
                "type": e.type.value,
                "value": e.value,
                "status": e.status.value,
                "report_count": e.report_count,
                "description": e.description,
                "admin_reason": reasons.get((e.type, e.value)),
                "updated_at": e.updated_at.isoformat(),
                **spread.get(
                    e.id, {"report_spread_minutes": 0.0, "coordinated_pattern_suspected": False}
                ),
            }
            for e in entries
        ],
    }


@router.post("/admin/whitelist")
def admin_add_whitelist(
    payload: AdminWhitelistRequest,
    db: Session = Depends(get_db),
    admin: CurrentUser = Depends(require_admin),
):
    return admin_add_whitelist_entry(db, payload.type, payload.value, payload.brand_name)


@router.post("/admin/confirm")
def admin_confirm(
    payload: AdminConfirmRequest,
    db: Session = Depends(get_db),
    admin: CurrentUser = Depends(require_admin),
):
    """Fait passer une entrée "pending" en "confirmed" — seule voie de confirmation."""
    return admin_confirm_entry(db, payload.type, payload.value, payload.reason, admin.email)


@router.post("/admin/reject")
def admin_reject(
    payload: AdminRejectRequest,
    db: Session = Depends(get_db),
    admin: CurrentUser = Depends(require_admin),
):
    """Rejette/retire une entrée, quel que soit son statut (pending ou confirmed)."""
    return admin_reject_entry(db, payload.type, payload.value, payload.reason, admin.email)


@router.get("/admin/audit")
def admin_audit(
    limit: int = 100,
    db: Session = Depends(get_db),
    admin: CurrentUser = Depends(require_admin),
):
    """Traçabilité complète (CRL-CDC-Module3-2.0 §8) — réservée aux administrateurs."""
    logs = get_audit_log(db, limit)
    return {
        "success": True,
        "message": "Journal d'audit",
        "data": [
            {
                "id": log.id,
                "entry_type": log.entry_type.value,
                "entry_value": log.entry_value,
                "action": log.action.value,
                "actor": log.actor,
                "reason": log.reason,
                "created_at": log.created_at.isoformat(),
            }
            for log in logs
        ],
    }


# =============================================================================
# PREUVES DE SIGNALEMENT
# =============================================================================
def _evidence_dict(e):
    return {
        "id": e.id,
        "filename": e.original_filename,
        "content_type": e.content_type,
        "size_bytes": e.size_bytes,
        "uploaded_at": e.uploaded_at.isoformat(),
    }


@router.post("/report/{report_id}/evidence")
async def upload_evidence(
    report_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Joint un fichier de preuve (capture d'écran, PDF) à un signalement déjà
    créé — appelée juste après POST /scam/report, avec l'identifiant
    "report_id" retourné par celui-ci. Réservé à l'auteur du signalement.
    """
    return save_evidence(db, report_id, current_user.user_id, file)


@router.get("/report/{report_id}/evidence")
def get_own_evidence(
    report_id: int,
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """Liste les preuves déjà jointes à l'un de ses propres signalements."""
    evidence = list_evidence_for_report(db, report_id, current_user.user_id)
    return {"success": True, "message": "Preuves du signalement", "data": [_evidence_dict(e) for e in evidence]}


@router.get("/admin/entries/{entry_id}/evidence")
def admin_list_entry_evidence(
    entry_id: int,
    db: Session = Depends(get_db),
    admin: CurrentUser = Depends(require_admin),
):
    """
    Vue d'ensemble, pour un administrateur, de toutes les preuves déposées
    sur une entrée (tous signalements confondus) — sert à évaluer la menace
    avant de confirmer ou rejeter l'entrée.
    """
    evidence = list_evidence_for_entry(db, entry_id)
    return {"success": True, "message": "Preuves de l'entrée", "data": [_evidence_dict(e) for e in evidence]}


@router.get("/evidence/{evidence_id}/download")
def download_evidence(
    evidence_id: int,
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Télécharge le fichier lui-même — réservé à un administrateur ou à
    l'auteur du signalement concerné (contrôle fait dans services.get_evidence_file).
    """
    evidence, path = get_evidence_file(db, evidence_id, current_user)
    return FileResponse(
        path, media_type=evidence.content_type, filename=evidence.original_filename
    )
