"""
services/scam-checker/models.py
================================================================================
Modèles ORM — Module Scam Checker (CyberSafe Connect)
================================================================================

Ce module définit les 5 tables de la base de références utilisée par le
Scam Checker pour les méthodes de détection 2 et 3 (CRL-CDC-Module3-2.0,
section 3.2 / 3.3) : liste noire, liste blanche, signalement, preuves
jointes, et journal d'audit.

--------------------------------------------------------------------------------
ROLE
--------------------------------------------------------------------------------
Ces modèles sont responsables de :

    • Stocker les éléments confirmés ou suspectés frauduleux (liste noire)
    • Stocker les domaines/numéros officiels des marques couvertes (liste
      blanche), pour éviter les faux positifs sur leurs communications réelles
    • Empêcher qu'un même compte signale plusieurs fois la même entrée
    • Tracer chaque changement de statut avec son auteur, pour la traçabilité

--------------------------------------------------------------------------------
POURQUOI 4 TABLES SEPAREES ET PAS UNE SEULE
--------------------------------------------------------------------------------
BlacklistEntry et WhitelistEntry ont des cycles de vie et des règles de
validation différents (une entrée blanche n'a pas de statut ni de compteur de
signalements). ScamReport existe séparément de BlacklistEntry pour pouvoir
imposer une contrainte d'unicité (un signalement par compte et par entrée)
sans alourdir la table principale. BlacklistAuditLog stocke le type et la
valeur de l'entrée en clair (pas seulement une clé étrangère) afin que
l'historique reste lisible même après suppression d'une entrée par un
administrateur (voir services.admin_reject_entry).

================================================================================
"""

from sqlalchemy import (
    Column,
    Integer,
    String,
    Enum,
    DateTime,
    ForeignKey,
    UniqueConstraint,
    Text,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from database import Base
from enums import EntryType, EntryStatus, AuditAction


# =============================================================================
# BLACKLIST ENTRY — LISTE NOIRE
# =============================================================================
# Un élément (numéro, URL ou domaine) suspecté ou confirmé frauduleux.
#
# DATABASE MAPPING
# -----------------------------------------------------------------------------
# Table : blacklist_entries
#
#     id            Identifiant unique (clé primaire)
#     type            Nature de la valeur : phone / url / domain (enums.EntryType)
#     value            Valeur normalisée (voir services.normalize_value) — un
#                     numéro de téléphone est par exemple stocké sans espace ni
#                     indicatif, pour que deux écritures du même numéro se
#                     retrouvent bien à la même ligne
#     status            Cycle de vie : pending / confirmed (enums.EntryStatus)
#                     — seul "confirmed" déclenche un verdict ROUGE
#                     automatique ; seul un administrateur peut confirmer
#                     (services.admin_confirm_entry), jamais automatiquement
#     report_count    Nombre de signalements communautaires reçus — sert à
#                     prioriser la revue administrateur, ne confirme plus
#                     rien automatiquement
#     description        Mode opératoire de l'arnaque, en texte libre —
#                     accumulé au fil des signalements citoyens (chaque
#                     nouveau témoignage est ajouté à la suite, séparé par
#                     un saut de ligne) plutôt qu'écrasé, pour garder trace
#                     de plusieurs récits indépendants sur la même entrée
#     created_at        Date de création de l'entrée
#     updated_at        Date de dernière modification (changement de statut)
#
# CONTRAINTE
# -----------------------------------------------------------------------------
# (type, value) est unique : on ne crée jamais deux lignes pour la même valeur,
# on incrémente report_count sur la ligne existante à la place.
# =============================================================================
class BlacklistEntry(Base):
    __tablename__ = "blacklist_entries"

    id = Column(Integer, primary_key=True, index=True)

    type = Column(Enum(EntryType), nullable=False)
    value = Column(String(255), nullable=False, index=True)

    status = Column(Enum(EntryStatus), nullable=False, default=EntryStatus.pending)
    report_count = Column(Integer, nullable=False, default=0)
    description = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Accès direct à tous les signalements individuels liés à cette entrée
    # (cascade="all, delete-orphan" : si l'entrée est supprimée — rejet admin
    # d'un signalement non fondé, ou retrait d'une entrée confirmée à tort —
    # ses signalements le sont aussi, ils n'ont plus de sens isolément).
    reports = relationship("ScamReport", back_populates="entry", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("type", "value", name="uq_blacklist_type_value"),
    )


# =============================================================================
# WHITELIST ENTRY — LISTE BLANCHE
# =============================================================================
# Domaine ou numéro officiel d'une marque couverte par le moteur de règles
# (Orange, MTN, banques...). Un élément trouvé ici neutralise l'indicateur
# "identité usurpée" de rules.py pour cette occurrence (CRL-CDC-Module3-2.0
# §3.2 : « neutralise ou réduit fortement le score »).
#
# DATABASE MAPPING
# -----------------------------------------------------------------------------
# Table : whitelist_entries
#
#     id            Identifiant unique
#     type            phone / url / domain
#     value            Valeur normalisée (même logique que BlacklistEntry)
#     brand_name        Nom de la marque associée (ex. "Orange"), à titre
#                     informatif pour le back-office administrateur
#     created_at        Date d'ajout
# =============================================================================
class WhitelistEntry(Base):
    __tablename__ = "whitelist_entries"

    id = Column(Integer, primary_key=True, index=True)

    type = Column(Enum(EntryType), nullable=False)
    value = Column(String(255), nullable=False, index=True)
    brand_name = Column(String(100), nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint("type", "value", name="uq_whitelist_type_value"),
    )


# =============================================================================
# SCAM REPORT — SIGNALEMENT INDIVIDUEL
# =============================================================================
# Une ligne par (compte, entrée) signalée. C'est cette table, et non un simple
# compteur sur BlacklistEntry, qui permet d'appliquer la règle « un
# signalement par compte et par entrée » (critère d'acceptation du CDC) : la
# contrainte d'unicité empêche un même compte d'incrémenter report_count
# plusieurs fois sur la même entrée.
#
# DATABASE MAPPING
# -----------------------------------------------------------------------------
# Table : scam_reports
#
#     id                    Identifiant unique
#     entry_id                Référence vers la BlacklistEntry signalée
#     reporter_user_id        Identifiant de l'utilisateur signalant (issu du
#                             token JWT du module auth — pas de table users
#                             locale, ce service ne fait que stocker l'id)
#     created_at                Date du signalement
# =============================================================================
class ScamReport(Base):
    __tablename__ = "scam_reports"

    id = Column(Integer, primary_key=True, index=True)

    entry_id = Column(Integer, ForeignKey("blacklist_entries.id"), nullable=False)
    reporter_user_id = Column(Integer, nullable=False, index=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    entry = relationship("BlacklistEntry", back_populates="reports")
    evidence = relationship("ReportEvidence", back_populates="report", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("entry_id", "reporter_user_id", name="uq_report_entry_user"),
    )


# =============================================================================
# REPORT EVIDENCE — PREUVES JOINTES A UN SIGNALEMENT
# =============================================================================
# Capture d'écran de conversation, document, ou tout fichier permettant à un
# administrateur d'évaluer la réalité de la menace avant de confirmer ou
# rejeter un signalement.
#
# DATABASE MAPPING
# -----------------------------------------------------------------------------
# Table : report_evidence
#
#     id                    Identifiant unique
#     report_id                Référence vers le ScamReport auquel le fichier
#                             est rattaché (un signalement peut avoir
#                             plusieurs preuves)
#     original_filename        Nom du fichier tel qu'envoyé par le navigateur
#                             — affiché à l'admin, jamais utilisé comme nom
#                             de fichier réel sur le disque (voir sécurité)
#     stored_filename        Nom réellement utilisé sur le disque (UUID),
#                             dans data/evidence/
#     content_type            Type MIME déclaré, validé contre une liste
#                             blanche à l'upload (services.py)
#     size_bytes                Taille du fichier, pour information et audit
#     uploaded_at            Date d'envoi
#
# SECURITE — POURQUOI stored_filename EST UN UUID, PAS original_filename
# -----------------------------------------------------------------------------
# Utiliser directement le nom de fichier fourni par l'utilisateur comme
# chemin sur le disque exposerait à une traversée de répertoire (ex. un nom
# de fichier "../../app/app.py") et à des collisions entre deux utilisateurs
# envoyant un fichier de même nom. Un UUID généré côté serveur élimine les
# deux risques.
# =============================================================================
class ReportEvidence(Base):
    __tablename__ = "report_evidence"

    id = Column(Integer, primary_key=True, index=True)

    report_id = Column(Integer, ForeignKey("scam_reports.id"), nullable=False)

    original_filename = Column(String(255), nullable=False)
    stored_filename = Column(String(100), nullable=False, unique=True)
    content_type = Column(String(100), nullable=False)
    size_bytes = Column(Integer, nullable=False)

    uploaded_at = Column(DateTime(timezone=True), server_default=func.now())

    report = relationship("ScamReport", back_populates="evidence")


# =============================================================================
# BLACKLIST AUDIT LOG — JOURNAL D'AUDIT
# =============================================================================
# Trace immuable de chaque changement de statut sur la base de références —
# exigence de sécurité explicite (CRL-CDC-Module3-2.0 §8, « Traçabilité »).
# Consultable uniquement par un administrateur (voir routes.admin_audit).
#
# DATABASE MAPPING
# -----------------------------------------------------------------------------
# Table : blacklist_audit_log
#
#     id                Identifiant unique
#     entry_type            Type de l'entrée concernée (dupliqué depuis
#                         BlacklistEntry — voir note ci-dessous)
#     entry_value            Valeur normalisée de l'entrée concernée
#     action                report / confirm / manual_add / reject
#                         (enums.AuditAction)
#     actor                Auteur de l'action, préfixé par son rôle : ex.
#                         "user:jean@mail.com", "admin:adams@cybersafeconnect.cm"
#                         — toujours un humain identifié, plus jamais "system"
#                         depuis le retrait de la confirmation automatique
#     reason                Motif texte libre (obligatoire pour un ajout
#                         manuel, une confirmation ou un rejet admin, absent
#                         pour un simple signalement)
#     created_at            Horodatage de l'action, indexé pour un tri rapide
#
# NOTE DE CONCEPTION — entry_type/entry_value plutôt qu'une clé étrangère
# -----------------------------------------------------------------------------
# entry_type et entry_value sont stockés en clair, et non comme une simple
# référence vers BlacklistEntry.id. Raison : quand un administrateur retire
# définitivement une entrée contestée à tort (action "removal"), la ligne
# BlacklistEntry est supprimée — mais son historique dans le journal d'audit
# doit rester lisible indéfiniment, y compris après cette suppression.
# =============================================================================
class BlacklistAuditLog(Base):
    __tablename__ = "blacklist_audit_log"

    id = Column(Integer, primary_key=True, index=True)

    entry_type = Column(Enum(EntryType), nullable=False)
    entry_value = Column(String(255), nullable=False, index=True)

    action = Column(Enum(AuditAction), nullable=False)
    actor = Column(String(120), nullable=False)
    reason = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
