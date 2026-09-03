"""
services/scam-checker/schemas.py
================================================================================
Schémas Pydantic — Module Scam Checker (CyberSafe Connect)
================================================================================

Modèles de validation des requêtes entrantes et de sérialisation des réponses
sortantes. Aucune de ces classes ne touche à la base de données — c'est
strictement le rôle de models.py.

--------------------------------------------------------------------------------
POURQUOI DES SCHEMAS SEPARES DES MODELES ORM
--------------------------------------------------------------------------------
models.BlacklistEntry (SQLAlchemy) décrit ce qui est stocké en base ; les
classes ci-dessous décrivent ce qu'un client HTTP a le droit d'envoyer et de
recevoir. Séparer les deux évite qu'un client puisse, par exemple, définir
lui-même le champ report_count d'une entrée en le glissant dans le corps
d'une requête — seuls les champs déclarés dans un schéma sont acceptés.
================================================================================
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from enums import EntryType, EntryStatus, Verdict, AuditAction, Language


# =============================================================================
# POST /scam/check
# =============================================================================
class ScamCheckRequest(BaseModel):
    # max_length=2000 : première ligne de défense contre un payload
    # surdimensionné, en complément de config.MAX_TEXT_LENGTH appliqué dans
    # routes.py.
    content: str = Field(..., min_length=1, max_length=2000)
    # Langue des motifs et conseils retournés — indépendante de la langue du
    # texte soumis (voir enums.Language). Le français reste le défaut pour ne
    # rien changer au comportement existant si le champ est omis.
    lang: Language = Language.fr


class ScamCheckResponseData(BaseModel):
    verdict: Verdict          # ROUGE / ORANGE / VERT
    score: int                  # Score agrégé (voir services.check_scam)
    motifs: list[str]          # Libellés des indicateurs déclenchés
    conseils: list[str]      # Conseils de prudence adaptés aux motifs
    is_url: bool              # True si le contenu a été traité comme une URL
    blacklisted: bool          # True si trouvé confirmé en liste noire (méthode 2)
    whitelisted: bool          # True si l'émetteur/domaine est en liste blanche (méthode 2)


# =============================================================================
# POST /scam/report — methode 3
# =============================================================================
class ScamReportRequest(BaseModel):
    type: EntryType
    value: str = Field(..., min_length=1, max_length=255)
    # Mode opératoire de l'arnaque, en texte libre — optionnel : un
    # signalement reste valide même sans description détaillée.
    description: str | None = Field(default=None, max_length=1000)


# =============================================================================
# POST /scam/admin/blacklist — back-office
# =============================================================================
class AdminBlacklistRequest(BaseModel):
    type: EntryType
    value: str = Field(..., min_length=1, max_length=255)
    reason: str = Field(..., min_length=1, max_length=1000)
    description: str | None = Field(default=None, max_length=1000)


# =============================================================================
# POST /scam/admin/whitelist — back-office
# =============================================================================
class AdminWhitelistRequest(BaseModel):
    type: EntryType
    value: str = Field(..., min_length=1, max_length=255)
    brand_name: str = Field(..., min_length=1, max_length=100)


# =============================================================================
# POST /scam/admin/confirm et POST /scam/admin/reject — back-office
# =============================================================================
# Seul un administrateur peut faire passer une entrée "pending" en
# "confirmed" — il n'existe plus de confirmation automatique par seuil de
# signalements (décision du 27/08/2026). "reject" fonctionne sur une entrée
# de n'importe quel statut : rejeter un signalement non fondé encore
# "pending", ou retirer une entrée "confirmed" dont on découvre après coup
# qu'elle ne l'aurait pas dû être — un seul outil de retrait, plutôt qu'un
# statut de contestation séparé.
# =============================================================================
class AdminConfirmRequest(BaseModel):
    type: EntryType
    value: str = Field(..., min_length=1, max_length=255)
    reason: str = Field(..., min_length=1, max_length=1000)


class AdminRejectRequest(BaseModel):
    type: EntryType
    value: str = Field(..., min_length=1, max_length=255)
    reason: str = Field(..., min_length=1, max_length=1000)


# =============================================================================
# GET /scam/blacklist — liste des entrées confirmées, ouverte à tout compte
# authentifié (pas seulement aux administrateurs) — voir routes.py
# =============================================================================
class BlacklistEntryOut(BaseModel):
    id: int
    type: EntryType
    value: str
    status: EntryStatus
    report_count: int
    description: str | None
    created_at: datetime
    updated_at: datetime

    # Permet de construire ce schéma directement depuis un objet ORM
    # (models.BlacklistEntry), sans conversion manuelle champ par champ.
    model_config = {"from_attributes": True}


class AuditLogOut(BaseModel):
    id: int
    entry_type: EntryType
    entry_value: str
    action: AuditAction
    actor: str
    reason: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}
