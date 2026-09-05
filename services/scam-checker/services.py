"""
services/scam-checker/services.py
================================================================================
Logique métier — Module Scam Checker (CyberSafe Connect)
================================================================================

Ce module orchestre les 4 méthodes de détection (CRL-CDC-Module3-2.0, section
3) et gère l'intégralité du cycle de vie de la liste noire : signalement,
confirmation/rejet par un administrateur (seul habilité à valider une entrée
depuis le 27/08/2026), et journal d'audit.

--------------------------------------------------------------------------------
ARCHITECTURE ROLE
--------------------------------------------------------------------------------
Comme dans services/auth/services.py, ce fichier ne contient AUCUNE
définition d'endpoint HTTP — c'est routes.py qui s'en charge. Cette séparation
permet de tester toute la logique de scoring et de gestion de la liste noire
sans avoir à démarrer un serveur HTTP.

--------------------------------------------------------------------------------
LES 4 METHODES DE DETECTION, ET QUI FAIT QUOI ICI
--------------------------------------------------------------------------------
    Méthode 1  (rules.py)         Moteur de règles textuelles bilingue
    Méthode 2  (ce fichier)         Recherche en liste noire / liste blanche
    Méthode 3  (ce fichier)         Signalement, confirmation/rejet admin
    Méthode 4  (url_analyzer.py)     Analyse heuristique de l'URL

check_scam() est le point d'entrée qui combine les 4 méthodes en un seul
verdict — c'est la fonction la plus importante de ce fichier.
================================================================================
"""

import os
import re
import uuid
from pathlib import Path

from fastapi import HTTPException, UploadFile
from sqlalchemy import func
from sqlalchemy.orm import Session

import rules
import url_analyzer
from config import (
    ALLOWED_EVIDENCE_TYPES,
    BLACKLIST_HIT_SCORE,
    BURST_MIN_REPORTS,
    BURST_WINDOW_MINUTES,
    EVIDENCE_DIR,
    MAX_EVIDENCE_PER_REPORT,
    MAX_EVIDENCE_SIZE_BYTES,
    SCORE_ORANGE_THRESHOLD,
    SCORE_ROUGE_THRESHOLD,
)
from enums import AuditAction, EntryStatus, EntryType, Verdict
from models import BlacklistAuditLog, BlacklistEntry, ReportEvidence, ScamReport, WhitelistEntry

# Numéro mobile camerounais : indicatif optionnel +237, puis un 6 suivi de 8
# chiffres (format des numéros Orange/MTN/Camtel mobile). Utilisé pour
# extraire un numéro de téléphone embarqué dans un texte libre (ex. le SMS
# "...contactez le 678901234...").
PHONE_PATTERN = re.compile(r"(?:\+?237)?\s?6\d{2}\s?\d{2}\s?\d{2}\s?\d{2}")

# =============================================================================
# CONSEILS DE PRUDENCE — TEXTE AFFICHE AU CITOYEN (bilingue FR/EN)
# =============================================================================
# Un conseil par famille de motif (correspondance par sous-chaîne, voir
# _build_conseils). Objectif du CDC (§1.1) : chaque verdict doit vulgariser,
# en langage clair, le risque encouru et les recours possibles — pas
# seulement afficher un score brut.
#
# Chaque entrée porte désormais {"fr": ..., "en": ...} : la langue RETOURNEE
# au citoyen (demande du 28/08/2026, sélecteur visible sur la page) est
# indépendante de la langue du texte qu'il a soumis — le moteur de règles
# détecte déjà les deux langues en entrée (rules.py), ceci ne concerne que la
# sortie. Le français reste la langue par défaut (enums.Language.fr).
# =============================================================================
CONSEILS_BY_MOTIF = {
    "demande d'argent": {
        "fr": "Ne transférez jamais d'argent ni de crédit suite à un message "
             "non sollicité, même s'il vous met la pression.",
        "en": "Never transfer money or airtime in response to an unsolicited "
             "message, even under pressure.",
    },
    "identité usurpée": {
        "fr": "Contactez l'entreprise ou l'institution citée via son site "
             "officiel ou son numéro connu, jamais via le message reçu.",
        "en": "Contact the company or institution through its official "
             "website or known number, never through the message you received.",
    },
    "promesse de gains": {
        "fr": "Aucun organisme sérieux ne vous fera gagner de l'argent sans "
             "que vous ayez participé à un concours réel.",
        "en": "No serious organization will make you win money without you "
             "having entered a real contest.",
    },
    "urgence": {
        "fr": "La pression à agir « immédiatement » est une technique "
             "classique d'arnaque : prenez le temps de vérifier.",
        "en": "Pressure to act \"immediately\" is a classic scam tactic — "
             "take the time to verify.",
    },
    "lien suspect": {
        "fr": "N'ouvrez pas ce lien. Vérifiez l'adresse officielle du "
             "service concerné directement dans votre navigateur.",
        "en": "Do not open this link. Check the official address of the "
             "service directly in your browser.",
    },
    "fautes d'orthographe": {
        "fr": "Les communications officielles contiennent rarement des "
             "fautes grossières.",
        "en": "Official communications rarely contain obvious spelling "
             "mistakes.",
    },
    "recrutement pyramidal": {
        "fr": "Méfiez-vous de toute offre d'emploi demandant un paiement "
             "initial ou basée sur le recrutement d'autres personnes.",
        "en": "Be wary of any job offer requiring an upfront payment or "
             "based on recruiting other people.",
    },
    "remboursement mobile money": {
        "fr": "Ne renvoyez jamais d'argent suite à un transfert reçu par "
             "« erreur » : vérifiez d'abord votre solde réel dans "
             "l'application officielle, et contactez votre opérateur si un "
             "appel insiste pour un remboursement.",
        "en": "Never send money back after a transfer received \"by "
             "mistake\": check your real balance in the official app first, "
             "and contact your operator if a call insists on a refund.",
    },
    "sextorsion": {
        "fr": "Ne payez jamais un maître-chanteur. Conservez les preuves et "
             "signalez ce cas via le module Signalement citoyen.",
        "en": "Never pay a blackmailer. Keep the evidence and report this "
             "case through the citizen reporting feature.",
    },
    "offre trop belle": {
        "fr": "Une offre trop avantageuse pour être vraie l'est généralement.",
        "en": "An offer that looks too good to be true usually is.",
    },
    "informations personnelles": {
        "fr": "Ne communiquez jamais votre code secret, mot de passe ou "
             "numéro de carte par SMS, email ou téléphone.",
        "en": "Never share your secret code, password, or card number by "
             "SMS, email, or phone.",
    },
    "HTTPS": {
        "fr": "Ce lien n'utilise pas de connexion sécurisée (HTTPS) — évitez "
             "d'y saisir des informations personnelles.",
        "en": "This link does not use a secure connection (HTTPS) — avoid "
             "entering personal information there.",
    },
    "typosquatting": {
        "fr": "Ce domaine imite le nom d'une marque connue avec une "
             "orthographe légèrement différente — ne vous y fiez pas.",
        "en": "This domain imitates a known brand name with slightly "
             "different spelling — do not trust it.",
    },
    "usurpation visuelle": {
        "fr": "Ce domaine utilise des caractères qui ressemblent visuellement "
             "à ceux d'une marque connue mais n'en font pas partie — tapez "
             "l'adresse officielle vous-même plutôt que de suivre ce lien.",
        "en": "This domain uses characters that look like those of a known "
             "brand but are not part of it — type the official address "
             "yourself rather than following this link.",
    },
    "punycode": {
        "fr": "Ce lien utilise un encodage international qui peut cacher "
             "des caractères visuellement identiques à ceux d'une marque "
             "connue — vérifiez l'adresse directement dans votre navigateur.",
        "en": "This link uses an international encoding that can hide "
             "characters visually identical to those of a known brand — "
             "check the address directly in your browser.",
    },
    "sous-domaines": {
        "fr": "La structure de ce lien est inhabituelle pour un site "
             "officiel.",
        "en": "This link's structure is unusual for an official website.",
    },
    "montant chiffré": {
        "fr": "Un montant précis annoncé par SMS ou email non sollicité est "
             "un signal d'alarme classique.",
        "en": "A precise amount announced by an unsolicited SMS or email is "
             "a classic red flag.",
    },
    "domaine officiel": {
        "fr": "Vérifiez que l'expéditeur utilise bien le domaine officiel "
             "de l'institution citée (ex. .gov.cm).",
        "en": "Check that the sender is using the official domain of the "
             "institution named (e.g. .gov.cm).",
    },
    "arnaque sentimentale": {
        "fr": "Une personne rencontrée en ligne qui ne peut jamais vous "
             "rencontrer en personne et demande de l'argent (colis bloqué, "
             "mission à l'étranger, carte cadeau...) est presque toujours "
             "une arnaque sentimentale.",
        "en": "Someone you met online who can never meet you in person and "
             "asks for money (a stuck parcel, an overseas deployment, a "
             "gift card...) is almost always a romance scam.",
    },
    "support technique": {
        "fr": "Aucune entreprise sérieuse ne vous contacte pour signaler un "
             "virus sur votre appareil. Ne rappelez pas, n'installez aucun "
             "logiciel de prise en main à distance.",
        "en": "No legitimate company contacts you to report a virus on your "
             "device. Do not call back, and never install remote-access "
             "software at their request.",
    },
    "adresse IP": {
        "fr": "Un lien qui pointe vers une adresse IP plutôt qu'un nom de "
             "domaine est presque toujours suspect pour une communication "
             "grand public.",
        "en": "A link pointing to a raw IP address instead of a domain name "
             "is almost always suspicious for a public-facing communication.",
    },
    "trompeuse": {
        "fr": "Ce lien contient un symbole « @ » qui masque le véritable "
             "site de destination — ne lui faites pas confiance.",
        "en": "This link contains an \"@\" symbol that hides the real "
             "destination site — do not trust it.",
    },
    "extension de domaine": {
        "fr": "Cette extension de domaine est très souvent utilisée pour des "
             "sites frauduleux en raison de son enregistrement gratuit.",
        "en": "This domain extension is very often used for fraudulent "
             "sites because it can be registered for free.",
    },
}

# Conseil générique ajouté systématiquement, en complément des conseils
# spécifiques ci-dessus, pour que la réponse ne soit jamais vide même si
# aucun motif précis n'a de conseil dédié (ex. un simple hit de liste noire).
VERDICT_BASE_ADVICE = {
    Verdict.rouge: {
        "fr": "Ne répondez pas à ce message et ne cliquez sur aucun lien "
             "qu'il contient. Signalez-le si possible.",
        "en": "Do not reply to this message and do not click any link it "
             "contains. Report it if possible.",
    },
    Verdict.orange: {
        "fr": "Restez prudent : vérifiez l'expéditeur par un autre moyen "
             "avant d'agir.",
        "en": "Stay cautious: verify the sender through another channel "
             "before acting.",
    },
    Verdict.vert: {
        "fr": "Aucun indicateur suspect détecté, mais restez vigilant si "
             "quelque chose vous semble anormal.",
        "en": "No suspicious indicator detected, but stay alert if "
             "something feels off.",
    },
}

# =============================================================================
# TRADUCTION DES MOTIFS (labels générés par rules.py / url_analyzer.py)
# =============================================================================
# rules.py et url_analyzer.py restent volontairement ignorants de la langue
# de sortie (voir leurs docstrings) : ils produisent toujours des motifs en
# français. La traduction n'intervient qu'ici, en toute fin de check_scam(),
# côté affichage — aucune logique de détection n'est dupliquée.
# =============================================================================
MOTIF_TRANSLATIONS_EN = {
    "demande d'argent": "money request",
    "identité usurpée": "impersonated identity",
    "promesse de gains irréalistes": "unrealistic prize promise",
    "montant chiffré précis": "precise stated amount",
    "urgence": "urgency",
    "lien suspect": "suspicious link",
    "fautes d'orthographe nombreuses": "numerous spelling mistakes",
    "recrutement pyramidal": "pyramid recruitment",
    "sextorsion": "sextortion",
    "faux remboursement mobile money": "fake mobile money refund",
    "offre trop belle": "too-good-to-be-true offer",
    "demande d'informations personnelles": "personal information request",
    "lien non sécurisé (http://)": "insecure link (http://)",
    "adresse e-mail hors domaine officiel (.gov.cm)": "email address outside official domain (.gov.cm)",
    "absence de HTTPS": "missing HTTPS",
    "sous-domaines suspects": "suspicious subdomains",
    "encodage punycode suspect (xn--)": "suspicious punycode encoding (xn--)",
    "longueur/complexité anormale du lien": "abnormal link length/complexity",
    "Élément confirmé en liste noire": "Element confirmed on the blacklist",
    "Aucun indicateur suspect détecté": "No suspicious indicator detected",
    "arnaque sentimentale (romance scam)": "romance scam",
    "faux support technique": "fake tech support",
    "adresse IP utilisée comme domaine": "IP address used as domain",
    "adresse trompeuse (symbole @ dans l'URL)": "deceptive address (@ symbol in URL)",
}

_TYPOSQUATTING_PREFIX_FR = "typosquatting probable de "
_TYPOSQUATTING_PREFIX_EN = "probable typosquatting of "

_ABUSED_TLD_PREFIX_FR = "extension de domaine à risque (."
_ABUSED_TLD_PREFIX_EN = "risky domain extension (."

_HOMOGLYPH_PREFIX_FR = "usurpation visuelle (homoglyphes) probable de "
_HOMOGLYPH_PREFIX_EN = "probable visual impersonation (homoglyphs) of "


def _translate_motif(motif: str, lang: str) -> str:
    """
    Traduit un motif français vers l'anglais si lang="en", sinon le retourne
    inchangé. Gère séparément les motifs à contenu dynamique — variantes de
    marque ou de TLD générées par url_analyzer.analyze_url — via un préfixe,
    plutôt qu'une entrée fixe par valeur possible dans MOTIF_TRANSLATIONS_EN.
    """
    if lang != "en":
        return motif
    if motif in MOTIF_TRANSLATIONS_EN:
        return MOTIF_TRANSLATIONS_EN[motif]
    if motif.startswith(_TYPOSQUATTING_PREFIX_FR):
        return _TYPOSQUATTING_PREFIX_EN + motif[len(_TYPOSQUATTING_PREFIX_FR):]
    if motif.startswith(_ABUSED_TLD_PREFIX_FR):
        return _ABUSED_TLD_PREFIX_EN + motif[len(_ABUSED_TLD_PREFIX_FR):]
    if motif.startswith(_HOMOGLYPH_PREFIX_FR):
        return _HOMOGLYPH_PREFIX_EN + motif[len(_HOMOGLYPH_PREFIX_FR):]
    return motif


# =============================================================================
# NORMALISATION DES VALEURS (methode 2/3)
# =============================================================================
def normalize_value(entry_type: EntryType, value: str) -> str:
    """
    Met une valeur dans une forme canonique unique avant toute comparaison ou
    tout stockage en base — sans ça, "+237 678 90 12 34", "678901234" et
    "237678901234" seraient traités comme 3 numéros différents alors qu'ils
    désignent la même ligne.

    phone : supprime espaces et "+", retire l'indicatif "237" en tête
    url / domain : minuscules, espaces superflus retirés
    """
    if entry_type == EntryType.phone:
        return re.sub(r"[\s+]", "", value).lstrip("237")
    return value.strip().lower()


# =============================================================================
# RECHERCHE EN BASE DE REFERENCES (methode 2)
# =============================================================================
def _lookup(db: Session, entry_type: EntryType, value: str) -> BlacklistEntry | None:
    """Recherche une valeur normalisée dans la liste noire (tous statuts confondus)."""
    normalized = normalize_value(entry_type, value)
    return (
        db.query(BlacklistEntry)
        .filter(BlacklistEntry.type == entry_type, BlacklistEntry.value == normalized)
        .first()
    )


def _lookup_whitelist(db: Session, entry_type: EntryType, value: str) -> WhitelistEntry | None:
    """Recherche une valeur normalisée dans la liste blanche."""
    normalized = normalize_value(entry_type, value)
    return (
        db.query(WhitelistEntry)
        .filter(WhitelistEntry.type == entry_type, WhitelistEntry.value == normalized)
        .first()
    )


def _extract_phone_numbers(content: str) -> list[str]:
    """Extrait tous les numéros camerounais embarqués dans un texte libre, normalisés."""
    return [normalize_value(EntryType.phone, m.group(0)) for m in PHONE_PATTERN.finditer(content)]


def _build_conseils(motifs: list[str], lang: str = "fr") -> list[str]:
    """
    Associe à chaque motif déclenché son conseil correspondant (recherche par
    sous-chaîne dans CONSEILS_BY_MOTIF), dans la langue demandée, sans
    doublon. `motifs` reste toujours en français ici (la correspondance par
    sous-chaîne est définie sur les clés françaises) — seule la langue du
    texte de conseil renvoyé change.
    """
    conseils = []
    for motif in motifs:
        for key, advice in CONSEILS_BY_MOTIF.items():
            text = advice[lang]
            if key in motif and text not in conseils:
                conseils.append(text)
                break
    return conseils


def _determine_verdict(score: int) -> Verdict:
    """Applique le barème de seuils (config.py) au score agrégé."""
    if score >= SCORE_ROUGE_THRESHOLD:
        return Verdict.rouge
    if score >= SCORE_ORANGE_THRESHOLD:
        return Verdict.orange
    return Verdict.vert


# =============================================================================
# POINT D'ENTREE PRINCIPAL — POST /scam/check
# =============================================================================
def check_scam(content: str, db: Session, lang: str = "fr") -> dict:
    """
    Analyse un texte ou une URL et retourne le verdict complet.

    Déroulé exact (CRL-CDC-Module3-2.0, section 4 — diagramme de séquence) :

        1. Détermine si le contenu est une URL ou un texte libre
        2. Extrait les candidats à vérifier en base : l'URL/le domaine si
           c'est un lien, sinon tout numéro de téléphone repéré dans le texte
        3. Méthode 2 : recherche ces candidats en liste noire ET en liste
           blanche
        4. Si un candidat est confirmé en liste noire → court-circuite tout
           le reste et retourne directement ROUGE (score 100) — un hit de
           liste noire suffit à lui seul, indépendamment du texte
        5. Sinon, méthode 1 : évalue le texte (rules.evaluate_text), en
           indiquant si un candidat était en liste blanche pour neutraliser
           l'indicateur d'usurpation de marque
        6. Si c'est une URL, méthode 4 : ajoute l'analyse structurelle du lien
        7. Additionne les points, détermine le verdict, construit les
           conseils de prudence

    lang : langue des motifs et conseils RETOURNES au citoyen ("fr" ou "en",
    voir enums.Language) — n'affecte jamais la détection elle-même, qui reste
    bilingue en entrée quelle que soit cette valeur (voir rules.py).
    """
    content = content.strip()
    is_url_input = url_analyzer.is_url(content)

    # --- Étape 2 : construction des candidats à vérifier en base -----------
    candidates: list[tuple[EntryType, str]] = []
    if is_url_input:
        domain = url_analyzer.urlparse(
            content if content.lower().startswith(("http://", "https://")) else f"http://{content}"
        ).netloc.lower()
        candidates.append((EntryType.url, content))
        if domain:
            candidates.append((EntryType.domain, domain))
    else:
        candidates.extend((EntryType.phone, p) for p in _extract_phone_numbers(content))

    # --- Étape 3 : recherche liste noire / liste blanche --------------------
    blacklisted = any(
        (entry := _lookup(db, etype, value)) is not None and entry.status == EntryStatus.confirmed
        for etype, value in candidates
    )
    whitelisted = any(
        _lookup_whitelist(db, etype, value) is not None for etype, value in candidates
    )

    # --- Étape 4 : court-circuit liste noire ---------------------------------
    if blacklisted:
        return {
            "verdict": Verdict.rouge,
            "score": BLACKLIST_HIT_SCORE,
            "motifs": [_translate_motif("Élément confirmé en liste noire", lang)],
            "conseils": [VERDICT_BASE_ADVICE[Verdict.rouge][lang]],
            "is_url": is_url_input,
            "blacklisted": True,
            "whitelisted": whitelisted,
        }

    # --- Étape 5 : méthode 1 (moteur de règles) ------------------------------
    matches = rules.evaluate_text(content, brand_whitelisted=whitelisted)

    # --- Étape 6 : méthode 4 (analyse d'URL), uniquement si pertinent --------
    if is_url_input:
        matches += url_analyzer.analyze_url(content)

    # --- Étape 7 : agrégation et verdict final -------------------------------
    score = sum(m.points for m in matches)
    verdict = _determine_verdict(score)
    # Le verdict est toujours accompagné d'au moins un motif explicite
    # (critère d'acceptation CRL-CDC-Module3-2.0 §6) — un message VERT sans
    # aucun indicateur déclenché doit quand même expliquer POURQUOI il est
    # jugé légitime, plutôt que de retourner une liste de motifs vide.
    # Les motifs français servent à la correspondance avec CONSEILS_BY_MOTIF
    # (clés définies en français) ; la traduction éventuelle n'intervient
    # qu'à la toute fin, sur la liste finalement retournée.
    motifs_fr = [m.motif for m in matches] or ["Aucun indicateur suspect détecté"]
    base_advice = VERDICT_BASE_ADVICE[verdict][lang]
    conseils = _build_conseils(motifs_fr, lang) or [base_advice]
    if base_advice not in conseils:
        conseils.append(base_advice)
    motifs = [_translate_motif(m, lang) for m in motifs_fr]

    return {
        "verdict": verdict,
        "score": score,
        "motifs": motifs,
        "conseils": conseils,
        "is_url": is_url_input,
        "blacklisted": False,
        "whitelisted": whitelisted,
    }


# =============================================================================
# JOURNAL D'AUDIT — ECRITURE
# =============================================================================
def _log_audit(db: Session, entry_type: EntryType, value: str, action: AuditAction,
                actor: str, reason: str | None = None) -> None:
    """
    Ajoute une ligne au journal d'audit (models.BlacklistAuditLog). N'appelle
    PAS db.commit() elle-même : c'est la fonction appelante qui décide du
    moment exact de la validation, pour que l'écriture du journal fasse
    partie de la même transaction que le changement qu'elle décrit (les deux
    réussissent ou échouent ensemble).
    """
    db.add(BlacklistAuditLog(
        entry_type=entry_type,
        entry_value=normalize_value(entry_type, value),
        action=action,
        actor=actor,
        reason=reason,
    ))


# =============================================================================
# METHODE 3 — SIGNALEMENT COMMUNAUTAIRE — POST /scam/report
# =============================================================================
def report_entry(
    db: Session,
    entry_type: EntryType,
    value: str,
    user_id: int,
    user_email: str,
    description: str | None = None,
    ip_address: str | None = None,
) -> dict:
    """
    Enregistre le signalement d'un citoyen connecté pour une entrée donnée.

    Règles appliquées :

        • Un signalement par compte et par entrée — imposé par la contrainte
          d'unicité de models.ScamReport, vérifiée explicitement ci-dessous
          pour retourner une erreur 400 claire plutôt qu'une erreur SQL brute
        • Une entrée déjà confirmée ne peut plus être signalée
        • AUCUNE confirmation automatique par seuil de signalements — décision
          du 27/08/2026 : seul un administrateur peut confirmer une entrée
          (voir admin_confirm_entry). L'entrée reste "pending" quel que soit
          le nombre de signalements reçus ; report_count sert uniquement
          d'indicateur pour prioriser la revue administrateur.

    description : mode opératoire de l'arnaque, en texte libre (optionnel).
    Accumulé sur l'entrée (pas écrasé) pour conserver plusieurs témoignages
    indépendants — utile à un administrateur pour évaluer la menace avant de
    confirmer, et affiché dans la liste publique des entrées confirmées
    (GET /scam/blacklist) une fois la revue faite.

    ip_address : adresse IP de la requête (optionnel) — sert uniquement au
    signal anti-brigading de get_report_spread (diversité des IP à l'origine
    des signalements d'une même entrée), jamais utilisée pour autre chose.
    """
    normalized = normalize_value(entry_type, value)

    # Récupère l'entrée existante, ou en crée une nouvelle en attente.
    entry = _lookup(db, entry_type, value)
    if entry is None:
        entry = BlacklistEntry(type=entry_type, value=normalized, status=EntryStatus.pending)
        db.add(entry)
        db.flush()  # nécessaire pour obtenir entry.id avant le commit final

    if entry.status == EntryStatus.confirmed:
        raise HTTPException(status_code=400, detail="Cette entrée est déjà confirmée")

    # Un signalement par compte et par entrée.
    already_reported = (
        db.query(ScamReport)
        .filter(ScamReport.entry_id == entry.id, ScamReport.reporter_user_id == user_id)
        .first()
    )
    if already_reported:
        raise HTTPException(
            status_code=400,
            detail="Vous avez déjà signalé cette entrée",
            headers={"X-Error-Code": "ALREADY_REPORTED"},
        )

    report = ScamReport(entry_id=entry.id, reporter_user_id=user_id, ip_address=ip_address)
    db.add(report)
    entry.report_count += 1

    if description:
        entry.description = (
            f"{entry.description}\n---\n{description}" if entry.description else description
        )

    _log_audit(db, entry_type, value, AuditAction.report, f"user:{user_email}", description)

    db.commit()
    db.refresh(entry)
    db.refresh(report)

    return {
        "success": True,
        "message": "Signalement enregistré, en attente de revue par un administrateur",
        "data": {
            "status": entry.status.value,
            "report_count": entry.report_count,
            "entry_id": entry.id,
            "report_id": report.id,
        },
    }


# =============================================================================
# BACK-OFFICE ADMIN — AJOUT MANUEL EN LISTE NOIRE — POST /scam/admin/blacklist
# =============================================================================
def admin_add_blacklist_entry(
    db: Session,
    entry_type: EntryType,
    value: str,
    reason: str,
    admin_email: str,
    description: str | None = None,
) -> dict:
    """
    Permet à un administrateur d'ajouter directement une entrée confirmée,
    sans attendre le seuil de signalements communautaires — cas d'usage :
    l'équipe CRL a connaissance directe d'une fraude (ex. relayée par la
    presse, comme les cas MINFOPRA ou PACD-PME du corpus de test).
    """
    normalized = normalize_value(entry_type, value)
    entry = _lookup(db, entry_type, value)
    if entry is None:
        entry = BlacklistEntry(type=entry_type, value=normalized, status=EntryStatus.confirmed)
        db.add(entry)
    else:
        entry.status = EntryStatus.confirmed

    if description:
        entry.description = description

    _log_audit(db, entry_type, value, AuditAction.manual_add, f"admin:{admin_email}", reason)
    db.commit()
    db.refresh(entry)

    return {"success": True, "message": "Entrée ajoutée à la liste noire", "data": {"id": entry.id}}


# =============================================================================
# LISTE PUBLIQUE DES ENTREES CONFIRMEES — GET /scam/blacklist
# =============================================================================
def get_confirmed_entries(db: Session, limit: int = 200) -> list[BlacklistEntry]:
    """
    Retourne les entrées confirmées de la liste noire (statut "confirmed"
    uniquement — jamais "pending", pour ne pas exposer des accusations non
    encore validées par un administrateur). Accessible à tout compte authentifié, pas
    seulement aux administrateurs : la transparence de la liste noire
    profite à toute la communauté, contrairement au journal d'audit complet
    (GET /scam/admin/audit) qui reste réservé aux administrateurs car il
    révèle l'identité des personnes ayant signalé une entrée.
    """
    return (
        db.query(BlacklistEntry)
        .filter(BlacklistEntry.status == EntryStatus.confirmed)
        .order_by(BlacklistEntry.updated_at.desc())
        .limit(limit)
        .all()
    )


# =============================================================================
# BACK-OFFICE ADMIN — TOUTES LES ENTREES — GET /scam/admin/entries
# =============================================================================
def get_all_entries(
    db: Session,
    status: EntryStatus | None = None,
    entry_type: EntryType | None = None,
    since=None,
    sort: str = "recent",
    limit: int = 200,
) -> list[BlacklistEntry]:
    """
    Vue d'ensemble administrateur, filtrable par statut, type et date
    (critère d'acceptation CRL-CDC-Module3-2.0 §3.5 : « Liste filtrable des
    entrées de la base de références (statut, type, date) »). Tous les
    filtres sont optionnels et combinables ; sans filtre, retourne toutes les
    entrées tous statuts confondus.

    since : ne retourne que les entrées mises à jour à partir de cette date
    (datetime) — typiquement utilisé pour revoir les signalements récents en
    priorité.

    sort : "recent" (défaut, dernière modification en premier) ou "reports"
    (nombre de signalements décroissant, pour prioriser la revue des entrées
    "pending" les plus corroborées — voir get_report_spread pour le signal de
    coordination complémentaire, calculé séparément par routes.py).
    """
    query = db.query(BlacklistEntry)
    if status is not None:
        query = query.filter(BlacklistEntry.status == status)
    if entry_type is not None:
        query = query.filter(BlacklistEntry.type == entry_type)
    if since is not None:
        query = query.filter(BlacklistEntry.updated_at >= since)

    if sort == "reports":
        query = query.order_by(BlacklistEntry.report_count.desc(), BlacklistEntry.updated_at.desc())
    else:
        query = query.order_by(BlacklistEntry.updated_at.desc())

    return query.limit(limit).all()


# =============================================================================
# MOTIF DE LA DERNIERE DECISION ADMINISTRATEUR (affichage citoyen + admin)
# =============================================================================
def get_admin_reasons(db: Session, entries: list[BlacklistEntry]) -> dict[tuple[EntryType, str], str]:
    """
    Pour chaque entrée fournie, retrouve le motif de la décision administrateur
    qui l'a fait passer (ou l'a maintenue) en liste noire — la dernière action
    "confirm" ou "manual_add" du journal d'audit pour ce (type, valeur).
    Affiché aux citoyens (GET /scam/blacklist) et aux administrateurs (GET
    /scam/admin/entries) pour justifier la présence d'une entrée sans jamais
    exposer l'identité d'un signalant (action "report", jamais lue ici).

    Filtre en Python plutôt qu'en SQL sur des tuples (type, valeur) : le
    volume du journal d'audit reste faible à cette échelle, et un IN sur
    tuple composite n'est pas portable de façon fiable entre SQLite et
    PostgreSQL (les deux backends supportés par ce service, voir config.py).
    """
    if not entries:
        return {}
    wanted = {(e.type, e.value) for e in entries}
    logs = (
        db.query(BlacklistAuditLog)
        .filter(BlacklistAuditLog.action.in_([AuditAction.confirm, AuditAction.manual_add]))
        .order_by(BlacklistAuditLog.created_at.desc())
        .all()
    )
    result: dict[tuple[EntryType, str], str] = {}
    for log in logs:
        key = (log.entry_type, log.entry_value)
        if key in wanted and key not in result:
            result[key] = log.reason
    return result


# =============================================================================
# ETALEMENT TEMPOREL DES SIGNALEMENTS (signal de priorisation admin)
# =============================================================================
def get_report_spread(db: Session, entry_ids: list[int]) -> dict[int, dict]:
    """
    Pour chaque entrée demandée, calcule deux signaux de diversité des
    signalements, indépendants l'un de l'autre :

        • report_spread_minutes / coordinated_pattern_suspected : écart
          temporel entre premier et dernier signalement — marque une
          "rafale" quand au moins BURST_MIN_REPORTS signalements arrivent en
          moins de BURST_WINDOW_MINUTES (voir config.py).
        • distinct_ip_count / low_diversity_suspected (05/09/2026, benchmark
          Truecaller) : nombre d'adresses IP distinctes à l'origine des
          signalements — marque un signal DIFFÉRENT et complémentaire, un
          même acteur signalant depuis plusieurs comptes mais une seule
          connexion, même étalé dans le temps (donc invisible à l'analyse
          temporelle seule).

    Un seul aller-retour base de données pour toute la liste (GROUP BY),
    plutôt qu'une requête par entrée.

    Ces signaux n'AUTOMATISENT rien : ils ne servent qu'à l'affichage dans
    le back-office (routes.admin_list_entries), à charge de l'administrateur
    d'en tenir compte ou non avant de confirmer/rejeter. distinct_ip_count
    est le seul détail exposé côté IP — jamais les adresses IP elles-mêmes
    (voir models.ScamReport, note sur ip_address).
    """
    if not entry_ids:
        return {}

    rows = (
        db.query(
            ScamReport.entry_id,
            func.min(ScamReport.created_at),
            func.max(ScamReport.created_at),
            func.count(ScamReport.id),
            func.count(func.distinct(ScamReport.ip_address)),
        )
        .filter(ScamReport.entry_id.in_(entry_ids))
        .group_by(ScamReport.entry_id)
        .all()
    )

    result: dict[int, dict] = {}
    for entry_id, first, last, count, distinct_ips in rows:
        spread_minutes = (last - first).total_seconds() / 60 if first and last else 0.0
        result[entry_id] = {
            "report_spread_minutes": round(spread_minutes, 1),
            "coordinated_pattern_suspected": (
                count >= BURST_MIN_REPORTS and spread_minutes <= BURST_WINDOW_MINUTES
            ),
            "distinct_ip_count": distinct_ips,
            # distinct_ips == 0 signifie "IP inconnue pour tous ces
            # signalements" (données antérieures à cette colonne, ou IP non
            # transmise) — jamais traité comme suspect par défaut, seul un
            # décompte confirmé à 1 déclenche ce signal.
            "low_diversity_suspected": count >= BURST_MIN_REPORTS and distinct_ips == 1,
        }
    return result


# =============================================================================
# BACK-OFFICE ADMIN — AJOUT MANUEL EN LISTE BLANCHE — POST /scam/admin/whitelist
# =============================================================================
# Endpoint non listé explicitement dans le tableau des 5 endpoints du CDC
# (section 7), mais requis pour que le back-office fonctionne réellement
# (section 3.6 : « Ajout manuel d'une entrée en liste noire OU en liste
# blanche ») — voir CRL - CDC - Module 3 - 2.0.docx §13 pour cette remarque.
# =============================================================================
def admin_add_whitelist_entry(db: Session, entry_type: EntryType, value: str, brand_name: str) -> dict:
    normalized = normalize_value(entry_type, value)
    existing = _lookup_whitelist(db, entry_type, value)
    if existing:
        raise HTTPException(status_code=400, detail="Cette entrée est déjà en liste blanche")

    entry = WhitelistEntry(type=entry_type, value=normalized, brand_name=brand_name)
    db.add(entry)
    db.commit()
    db.refresh(entry)

    return {"success": True, "message": "Entrée ajoutée à la liste blanche", "data": {"id": entry.id}}


# =============================================================================
# BACK-OFFICE ADMIN — VALIDATION D'UN SIGNALEMENT — POST /scam/admin/confirm
# =============================================================================
# Seul point d'entrée qui fait passer une entrée "pending" en "confirmed" —
# il n'existe plus de confirmation automatique par seuil de signalements
# (décision du 27/08/2026, voir enums.EntryStatus). Un administrateur revoit
# le mode opératoire accumulé (BlacklistEntry.description) et les preuves
# jointes (list_evidence_for_entry) avant de confirmer.
# =============================================================================
def admin_confirm_entry(db: Session, entry_type: EntryType, value: str, reason: str, admin_email: str) -> dict:
    entry = _lookup(db, entry_type, value)
    if entry is None or entry.status != EntryStatus.pending:
        raise HTTPException(status_code=404, detail="Aucune entrée en attente à confirmer")

    entry.status = EntryStatus.confirmed
    _log_audit(db, entry_type, value, AuditAction.confirm, f"admin:{admin_email}", reason)
    db.commit()
    return {"success": True, "message": "Entrée confirmée"}


# =============================================================================
# BACK-OFFICE ADMIN — REJET / RETRAIT D'UNE ENTREE — POST /scam/admin/reject
# =============================================================================
# Outil de retrait unique, quel que soit le statut de l'entrée :
#
#     • Sur une entrée "pending" : rejette un signalement jugé non fondé
#       (l'entrée et ses signalements sont supprimés, rien n'est jamais
#       passé en liste noire)
#     • Sur une entrée "confirmed" : sert de garde-fou a posteriori si un
#       administrateur découvre après coup qu'une confirmation était une
#       erreur — remplace l'ancien mécanisme de contestation citoyenne, qui
#       n'a plus lieu d'être puisqu'aucune confirmation n'échappe désormais
#       à une revue humaine
#
# Le journal d'audit, lui, conserve la trace de cette suppression — voir
# models.py, note de conception sur BlacklistAuditLog.
# =============================================================================
def admin_reject_entry(db: Session, entry_type: EntryType, value: str, reason: str, admin_email: str) -> dict:
    entry = _lookup(db, entry_type, value)
    if entry is None:
        raise HTTPException(status_code=404, detail="Entrée introuvable")

    _log_audit(db, entry_type, value, AuditAction.reject, f"admin:{admin_email}", reason)
    db.delete(entry)
    db.commit()
    return {"success": True, "message": "Entrée rejetée / retirée de la liste noire"}


# =============================================================================
# BACK-OFFICE ADMIN — CONSULTATION DU JOURNAL D'AUDIT — GET /scam/admin/audit
# =============================================================================
def get_audit_log(db: Session, limit: int = 100) -> list[BlacklistAuditLog]:
    """Retourne les entrées les plus récentes du journal d'audit, triées par date décroissante."""
    return (
        db.query(BlacklistAuditLog)
        .order_by(BlacklistAuditLog.created_at.desc())
        .limit(limit)
        .all()
    )


# =============================================================================
# PREUVES DE SIGNALEMENT — POST /scam/report/{report_id}/evidence
# =============================================================================
def _get_owned_report(db: Session, report_id: int, user_id: int) -> ScamReport:
    """
    Récupère un signalement en vérifiant qu'il appartient bien à
    l'utilisateur courant — une personne ne peut joindre une preuve qu'à
    son PROPRE signalement, jamais à celui d'un autre compte.
    """
    report = db.query(ScamReport).filter(ScamReport.id == report_id).first()
    if report is None:
        raise HTTPException(status_code=404, detail="Signalement introuvable")
    if report.reporter_user_id != user_id:
        raise HTTPException(
            status_code=403,
            detail="Vous ne pouvez joindre une preuve qu'à votre propre signalement",
            headers={"X-Error-Code": "FORBIDDEN"},
        )
    return report


def save_evidence(db: Session, report_id: int, user_id: int, file: UploadFile) -> dict:
    """
    Enregistre un fichier de preuve (capture d'écran, PDF...) joint à un
    signalement, pour permettre à un administrateur d'évaluer la réalité de
    la menace avant de confirmer ou rejeter un signalement.

    Contrôles de sécurité, dans l'ordre :

        1. Le signalement existe et appartient à l'appelant (_get_owned_report)
        2. Le nombre de preuves déjà jointes ne dépasse pas
           config.MAX_EVIDENCE_PER_REPORT (anti-abus de stockage)
        3. Le type MIME déclaré fait partie de la liste blanche
           (config.ALLOWED_EVIDENCE_TYPES) — aucun format exécutable accepté
        4. La taille ne dépasse pas config.MAX_EVIDENCE_SIZE_BYTES
        5. Le fichier est écrit sous un nom généré côté serveur (UUID),
           jamais sous le nom fourni par le client (voir models.py, note de
           sécurité sur ReportEvidence.stored_filename)
    """
    report = _get_owned_report(db, report_id, user_id)

    existing_count = (
        db.query(ReportEvidence).filter(ReportEvidence.report_id == report.id).count()
    )
    if existing_count >= MAX_EVIDENCE_PER_REPORT:
        raise HTTPException(
            status_code=400,
            detail=f"Maximum {MAX_EVIDENCE_PER_REPORT} preuves par signalement",
        )

    if file.content_type not in ALLOWED_EVIDENCE_TYPES:
        raise HTTPException(
            status_code=400,
            detail="Type de fichier non autorisé (image PNG/JPEG/WebP ou PDF uniquement)",
        )

    contents = file.file.read()
    if len(contents) > MAX_EVIDENCE_SIZE_BYTES:
        raise HTTPException(
            status_code=400,
            detail=f"Fichier trop volumineux (max {MAX_EVIDENCE_SIZE_BYTES // (1024 * 1024)} Mo)",
        )

    extension = os.path.splitext(file.filename or "")[1][:10]
    stored_filename = f"{uuid.uuid4().hex}{extension}"

    evidence_dir = Path(EVIDENCE_DIR)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / stored_filename).write_bytes(contents)

    evidence = ReportEvidence(
        report_id=report.id,
        original_filename=(file.filename or "fichier")[:255],
        stored_filename=stored_filename,
        content_type=file.content_type,
        size_bytes=len(contents),
    )
    db.add(evidence)
    db.commit()
    db.refresh(evidence)

    return {
        "success": True,
        "message": "Preuve enregistrée",
        "data": {"id": evidence.id, "filename": evidence.original_filename},
    }


def list_evidence_for_report(db: Session, report_id: int, user_id: int) -> list[ReportEvidence]:
    """Liste les preuves d'un signalement — réservé à son auteur (voir _get_owned_report)."""
    report = _get_owned_report(db, report_id, user_id)
    return report.evidence


def list_evidence_for_entry(db: Session, entry_id: int) -> list[ReportEvidence]:
    """
    Liste TOUTES les preuves rattachées à une entrée (tous signalements
    confondus) — réservé aux administrateurs (routes.py), pour évaluer la
    menace avant de confirmer ou rejeter un signalement.
    """
    return (
        db.query(ReportEvidence)
        .join(ScamReport, ReportEvidence.report_id == ScamReport.id)
        .filter(ScamReport.entry_id == entry_id)
        .order_by(ReportEvidence.uploaded_at.desc())
        .all()
    )


def get_evidence_file(db: Session, evidence_id: int, current_user) -> tuple[ReportEvidence, Path]:
    """
    Résout le chemin disque d'une preuve pour téléchargement, en vérifiant
    que l'appelant a le droit de la voir : un administrateur (tout accès),
    ou l'auteur du signalement auquel elle est jointe (et lui seul).
    """
    evidence = db.query(ReportEvidence).filter(ReportEvidence.id == evidence_id).first()
    if evidence is None:
        raise HTTPException(status_code=404, detail="Preuve introuvable")

    is_owner = evidence.report.reporter_user_id == current_user.user_id
    is_admin = current_user.role == "admin"
    if not is_owner and not is_admin:
        raise HTTPException(
            status_code=403,
            detail="Accès refusé à cette preuve",
            headers={"X-Error-Code": "FORBIDDEN"},
        )

    path = Path(EVIDENCE_DIR) / evidence.stored_filename
    if not path.exists():
        raise HTTPException(status_code=404, detail="Fichier de preuve manquant sur le serveur")

    return evidence, path
