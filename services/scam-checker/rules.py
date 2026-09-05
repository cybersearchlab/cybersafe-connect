"""
services/scam-checker/rules.py
================================================================================
Méthode 1 — Moteur de règles bilingue (CRL-CDC-Module3-2.0, section 3.1 / 3.5)
================================================================================

Analyse un texte brut (SMS, email, message WhatsApp, ou une URL traitée comme
texte) et retourne la liste des indicateurs d'arnaque détectés, chacun avec
son nombre de points. C'est le point d'entrée de la détection : services.py
l'appelle systématiquement, que l'entrée soit un texte libre ou une URL.

--------------------------------------------------------------------------------
ROLE
--------------------------------------------------------------------------------
    • Détecter les indicateurs textuels d'arnaque (urgence, demande d'argent,
      promesse de gain, usurpation de marque, fautes d'orthographe...)
    • Couvrir le français ET l'anglais dès la v1 (critère d'acceptation du
      CDC — le Cameroun est officiellement bilingue, et les arnaques y
      circulent dans les deux langues)
    • Ne jamais exécuter ni interpréter le contenu soumis : chaque règle est
      une simple comparaison de motifs (mots-clés, expressions régulières)

--------------------------------------------------------------------------------
LE BAREME DE POINTS N'ETAIT PAS CHIFFRE DANS LES CDC SOURCES
--------------------------------------------------------------------------------
Les cahiers des charges (CRL-CDC-1.0 et CRL-CDC-Module3-2.0) définissaient les
indicateurs et les seuils de verdict (ROUGE >= 70, ORANGE 30-69, VERT < 30),
mais jamais la valeur de points de chaque indicateur individuel. Le barème
ci-dessous est une proposition (documentée dans CRL - CDC - Module 3 -
2.0.docx, section 3.5), vérifiée par exécution réelle contre les 3 exemples de
référence du corpus de test (§9.1) :

    ROUGE  — « Félicitations ! Vous avez gagné 500 000 FCFA... »  → score 70
    ORANGE — « ...offre spéciale... cliquez ici : bit.ly/xyz123 » → score 35
    VERT   — « ...votre facture ENEO... eneocameroun.com... »     → score 0

--------------------------------------------------------------------------------
DEUX INDICATEURS AJOUTES, ABSENTS DU BAREME D'ORIGINE
--------------------------------------------------------------------------------
Le corpus de test réel (CRL-CDC-Module3-2.0, §9.2) documente des arnaques
camerounaises (recrutement pyramidal QNET/IGNITE/UNIMEC, sextorsion) que le
barème d'origine ne couvrait pas encore. Ces deux catégories sont ajoutées ici
en tant qu'indicateurs à part entière (voir PYRAMID_RECRUITMENT_KEYWORDS et
SEXTORTION_KEYWORDS ci-dessous).
================================================================================
"""

import re
import unicodedata
from dataclasses import dataclass
from difflib import SequenceMatcher


# =============================================================================
# RESULTAT D'UNE REGLE DECLENCHEE
# =============================================================================
@dataclass
class RuleMatch:
    motif: str      # Libellé affiché au citoyen (ex. "demande d'argent")
    points: int      # Contribution au score total (voir config.py pour les seuils)


# =============================================================================
# RACCOURCISSEURS DE LIENS CONNUS
# =============================================================================
# Comptés une seule fois ici (méthode 1), pour éviter un double comptage avec
# url_analyzer.py (méthode 4) — voir url_analyzer.py, qui exclut
# explicitement les domaines de cette liste de sa propre analyse structurelle.
# =============================================================================
LINK_SHORTENERS = [
    "bit.ly", "tinyurl.com", "cutt.ly", "is.gd", "t.co", "ow.ly", "shorte.st",
    "rebrand.ly", "goo.gl", "buff.ly",
]

# =============================================================================
# MARQUES CONNUES (indicateur "identité usurpée", +30)
# =============================================================================
# La simple mention d'une de ces marques est un indicateur ROUGE-tier — SAUF
# si l'émetteur/domaine est confirmé en liste blanche (méthode 2), auquel cas
# cet indicateur est volontairement ignoré (voir evaluate_text,
# paramètre brand_whitelisted). C'est ce mécanisme qui évite de pénaliser à
# tort les communications légitimes d'Orange, MTN ou des banques.
# =============================================================================
BRAND_KEYWORDS = [
    "orange", "mtn", "mtn money", "orange money", "afriland", "ecobank",
    "uba", "bicec", "sgbc", "société générale",
]

# Racines de marque (>= 4 lettres, condition de _has_fuzzy_brand_variant)
# utilisées pour repérer une marque déformée volontairement en texte libre
# (ex. "0range", "Ecobnak") — "mtn" et "uba" sont trop courtes pour qu'un
# ratio de ressemblance soit fiable, voir _has_fuzzy_brand_variant.
BRAND_FUZZY_REFERENCE = ["orange", "afriland", "ecobank", "bicec"]

# =============================================================================
# INSTITUTIONS OFFICIELLES (indicateur "adresse e-mail hors domaine officiel")
# =============================================================================
# Cas réel MINFOPRA (corpus de test §9.2) : un faux communiqué usurpant le nom
# d'une institution, envoyé depuis une adresse ne correspondant pas au domaine
# officiel .gov.cm. Cette liste sert à repérer la MENTION de l'institution ;
# c'est ensuite le domaine de l'adresse e-mail trouvée dans le texte qui est
# comparé au domaine officiel attendu (voir plus bas dans evaluate_text).
# =============================================================================
INSTITUTION_KEYWORDS = [
    "minfopra", "ministère", "ministere", "antic", "pacd-pme", "pacd pme",
    "gouvernement", "government", "ministry",
]

# =============================================================================
# DEMANDE D'ARGENT IMMEDIATE (+30 — indicateur ROUGE-tier le plus lourd)
# =============================================================================
# Expressions régulières plutôt que simples mots-clés : "contacter" seul est
# beaucoup trop fréquent dans un message légitime pour être un indicateur
# fiable ; c'est la combinaison "contactez ... (pour) retirer/recevoir" qui
# signale une demande d'action financière.
# =============================================================================
MONEY_REQUEST_PATTERNS = [
    r"\bcontactez\b.{0,40}\b(retirer|recevoir|percevoir)\b",
    r"\bretirer votre gain\b", r"\benvoyez\b.{0,20}\bfrais\b",
    r"\bpay(ez|ment)\b.{0,20}\bfee\b", r"\bsend money\b",
    r"\bfrais de dossier\b", r"\bfrais d'inscription\b",
    r"\bdeposit fee\b", r"\bprocessing fee\b",
]

# =============================================================================
# URGENCE (+20)
# =============================================================================
# Technique classique d'ingénierie sociale : pousser la victime à agir avant
# d'avoir eu le temps de vérifier. Bilingue FR/EN dès la v1.
# =============================================================================
URGENCY_KEYWORDS = [
    "dernière chance", "derniere chance", "aujourd'hui seulement",
    "offre limitée", "offre limitee", "immédiatement", "immediatement",
    "urgent", "expire", "avant le", "last chance", "today only",
    "act now", "limited time", "expires today", "immediately",
]

# =============================================================================
# PROMESSE DE GAIN IRREALISTE (+25, +15 supplémentaires si montant chiffré)
# =============================================================================
# Deux familles de formulation couvertes : le gain de type loterie
# ("vous avez gagné...") ET la fausse subvention/aide financière de type
# institutionnel — ajoutée après avoir constaté que le cas réel PACD-PME
# (corpus de test §9.2 : fausse subvention de 500 000 à 2 000 000 FCFA
# usurpant un programme d'aide aux PME) ne déclenchait aucun indicateur avec
# la seule liste orientée loterie.
GAIN_KEYWORDS = [
    "félicitations", "felicitations", "vous avez gagné", "vous avez gagne",
    "gain exceptionnel", "gagnant", "tirage au sort", "cadeau gratuit",
    "congratulations", "you have won", "you won", "free gift", "lucky winner",
    "claim your prize",
    "subvention", "aide financière", "aide financiere", "financement accordé",
    "financement accorde", "programme d'appui", "grant awarded",
    "financial aid", "funding approved",
]

# Montant chiffré précis (ex. « 500 000 FCFA ») — renforce l'indicateur de
# gain irréaliste, sur le modèle du cas réel PACD-PME (corpus de test §9.2 :
# « renforce l'indicateur promesse de gains chiffrée et datée »). N'est
# évalué que si GAIN_KEYWORDS a déjà déclenché (voir evaluate_text) : un
# simple montant chiffré seul, sans autre indicateur de gain, n'est pas
# suspect en lui-même (ex. une facture).
CURRENCY_AMOUNT_PATTERN = r"\d[\d\s]{2,}\s?(fcfa|cfa|xaf|f\s?cfa|\$|usd|eur|€)"

# =============================================================================
# FAUX REMBOURSEMENT MOBILE MONEY (+30 — nouvel indicateur, benchmark 28/08/2026)
# =============================================================================
# Schéma documenté comme l'un des vecteurs de fraude mobile money les plus
# répandus en Afrique (GIABA, GSMA — voir README.md, section « Pistes
# d'enrichissement ») : l'escroc envoie un faux SMS de confirmation de
# transfert reçu, puis appelle ou relance en prétendant une erreur pour se
# faire renvoyer l'argent (ou seulement la « différence ») — la victime
# renvoie des fonds réels en réponse à un transfert souvent jamais réellement
# reçu. Distinct de MONEY_REQUEST_PATTERNS : ici c'est un remboursement qui
# est demandé, pas un paiement direct, d'où une formulation différente que
# les motifs existants ne couvraient pas.
# =============================================================================
MOBILE_MONEY_REFUND_KEYWORDS = [
    "erreur de transfert", "envoyé par erreur", "envoye par erreur",
    "transfert par erreur", "renvoyez la différence", "renvoyez la difference",
    "renvoyer la différence", "renvoyer la difference",
    "remboursez la différence", "remboursez la difference",
    "mauvais numéro", "mauvais numero",
    "sent by mistake", "sent to you by mistake", "please return",
    "wrong number transfer", "refund the difference", "return the extra",
    "return the excess",
]

# =============================================================================
# OFFRE TROP BELLE (+15 — indicateur ORANGE-tier)
# =============================================================================
OFFER_TOO_GOOD_KEYWORDS = [
    "offre spéciale", "offre speciale", "promotion exceptionnelle",
    "special offer", "amazing deal", "exclusive offer",
]

# =============================================================================
# DEMANDE D'INFORMATIONS PERSONNELLES (+15 — indicateur ORANGE-tier)
# =============================================================================
# Aucune institution légitime ne demande un code secret ou un mot de passe
# par SMS/email — un indicateur fort de phishing.
# =============================================================================
PERSONAL_INFO_KEYWORDS = [
    "code secret", "code confidentiel", "numéro de carte", "numero de carte",
    "mot de passe", "pin code", "otp", "secret code", "password",
    "card number", "cvv",
]

# =============================================================================
# RECRUTEMENT PYRAMIDAL (+35 — nouvel indicateur, cas QNET/IGNITE/UNIMEC)
# =============================================================================
# Ajouté suite au cas réel documenté dans le corpus de test (§9.2) : réseau de
# recrutement pyramidal démantelé en juin 2026 (13 suspects arrêtés, 600+
# victimes), non couvert par le barème d'origine du CDC général.
#
# Points fixés à 35 (et non 25 comme dans une première version) : un message
# de recrutement pyramidal réel testé contre ce barème (« rejoignez notre
# réseau... parrainage rémunéré... emploi à l'étranger ») ne déclenche que
# CET indicateur, aucun autre — à 25 points il resterait sous le seuil ORANGE
# (30) et serait classé VERT à tort, ce qui est inacceptable vu la gravité
# réelle de ce type de cas (réseau de traite humaine).
# =============================================================================
PYRAMID_RECRUITMENT_KEYWORDS = [
    "recrutement en chaîne", "recrutement en chaine", "devenez indépendant",
    "devenez independant", "réseau de distributeurs", "reseau de distributeurs",
    "parrainage", "emploi à l'étranger", "emploi a l'etranger", "ibo",
    "network marketing", "recruit others", "downline", "job abroad",
    "recruitment bonus",
]

# =============================================================================
# SEXTORSION (+30 — nouvel indicateur, catégorie séparée)
# =============================================================================
# Traité comme une catégorie de mots-clés à part (et non comme une variante de
# "demande d'argent"), conformément au corpus de test §9.2 : la menace de
# diffusion de contenu compromettant est un schéma d'arnaque distinct des
# arnaques financières directes, qui mérite ses propres conseils de prudence
# (voir services.CONSEILS_BY_MOTIF).
# =============================================================================
SEXTORTION_KEYWORDS = [
    "diffuser vos photos", "diffuser vos vidéos", "diffuser vos videos",
    "chantage", "vidéo compromettante", "video compromettante",
    "leak your photos", "leak your video", "blackmail", "compromising video",
    "share your pictures",
]

# =============================================================================
# FAUTES D'ORTHOGRAPHE NOMBREUSES (+15 — heuristique best-effort)
# =============================================================================
# Détecter automatiquement "beaucoup de fautes" de façon fiable nécessiterait
# un correcteur orthographique complet, hors périmètre v1. Cette liste
# reconnaît plutôt des déformations typiques déjà observées dans des messages
# frauduleux réels (ex. "flicitation" pour "félicitation", anglicismes
# calqués) — un compromis pragmatique, à enrichir avec l'usage réel.
# =============================================================================
SPELLING_ERROR_PATTERNS = [
    r"\bflicitation", r"\bgagnee?\b.{0,3}\!", r"\bcliquer ici\b",
    r"\bveuillez\b.{0,5}\bcliquer\b", r"\bcongratulation\b(?!s)",
    r"\bclick here now\b",
]

# =============================================================================
# VARIANTES APPROCHANTES D'UN MOT-CLE CONNU (ressemblance >= 90 %)
# =============================================================================
# Les motifs fixes ci-dessus (SPELLING_ERROR_PATTERNS) ne couvrent que les
# déformations déjà observées et explicitement listées. Ils ratent toute
# variante nouvelle d'un mot-clé à fort pouvoir de détection (ex.
# "felicitationss", "urgnt", "gratuiit") — une déformation volontaire (ou une
# simple faute de frappe) suffit à échapper à une comparaison de mots-clés
# exacte. Cette section ajoute une comparaison par SIMILARITE plutôt que par
# égalité stricte : chaque mot du texte soumis (>= 4 lettres) est comparé à
# une liste de référence de mots-clés à fort signal, et un ratio de
# ressemblance >= SPELLING_FUZZY_THRESHOLD (90 %, valeur demandée) déclenche
# l'indicateur — SAUF en cas d'égalité stricte (ratio 1.0), qui n'est pas une
# faute mais l'orthographe correcte du mot, déjà couverte par les listes de
# mots-clés dédiées (GAIN_KEYWORDS, URGENCY_KEYWORDS...).
#
# Implémentation en stdlib pur (difflib.SequenceMatcher) — pas de nouvelle
# dépendance. Les accents sont retirés avant comparaison (_strip_accents) car
# leur absence est la variation la plus fréquente dans un SMS frauduleux
# ("felicitation" pour "félicitation") et ne doit pas, à elle seule, réduire
# le ratio de ressemblance.
# =============================================================================
SPELLING_REFERENCE_WORDS = [
    # Français — mots-clés à fort signal, régulièrement déformés
    "felicitations", "gratuit", "urgent", "gagnant", "gagne", "cliquez",
    "verifiez", "confirmez", "immediatement", "virement",
    # Anglais
    "congratulations", "verify", "confirm", "immediately", "winner",
    "click", "free", "prize", "urgent",
]

SPELLING_FUZZY_THRESHOLD = 0.90

# =============================================================================
# ARNAQUE SENTIMENTALE / ROMANCE SCAM (+30 — nouvel indicateur, 05/09/2026)
# =============================================================================
# Catégorie documentée comme un vide de couverture régionale lors du
# benchmark du 28/08/2026 (DénonceTonScammeur — base collaborative dédiée
# aux romance scams ouest-africains). Plutôt que des phrases génériques de
# déclaration d'amour (trop fréquentes dans des messages légitimes, risque
# de faux positif), les mots-clés ciblent les DISPOSITIFS narratifs les plus
# documentés du schéma : colis bloqué en douane, prétexte d'affectation
# militaire à l'étranger empêchant toute rencontre en personne, et demande
# de paiement par carte cadeau (intraçable) — trois signaux rarement
# présents dans une conversation authentique.
# =============================================================================
ROMANCE_SCAM_KEYWORDS = [
    "colis bloqué en douane", "colis bloqué à la douane", "colis bloque en douane",
    "frais de dédouanement", "frais de douanement",
    "parcel stuck at customs", "package stuck in customs", "customs clearance fee",
    "en mission militaire à l'étranger", "en mission militaire a l'etranger",
    "on a military mission", "deployed overseas",
    "je ne peux pas venir moi-même", "je ne peux pas venir moi-meme",
    "i cannot travel to meet you", "cannot come to meet you in person",
    "carte cadeau itunes", "itunes gift card", "google play gift card",
    "carte cadeau amazon", "amazon gift card",
]

# =============================================================================
# FAUX SUPPORT TECHNIQUE (+25 — nouvel indicateur, 05/09/2026)
# =============================================================================
# Schéma classique : un message ou un pop-up prétend qu'un virus a été
# détecté et pousse la victime à appeler un numéro ou installer un logiciel
# de prise en main à distance (TeamViewer, AnyDesk) — jamais couvert par le
# barème d'origine, qui ne visait que les arnaques financières directes.
# =============================================================================
TECH_SUPPORT_KEYWORDS = [
    "votre ordinateur est infecté", "votre ordinateur est infecte",
    "your computer is infected", "virus détecté sur votre appareil",
    "virus detecte sur votre appareil", "virus detected on your device",
    "support microsoft", "microsoft support", "windows support",
    "n'éteignez pas votre ordinateur", "n'eteignez pas votre ordinateur",
    "do not turn off your computer", "accès à distance à votre ordinateur",
    "acces a distance a votre ordinateur", "remote access to your computer",
    "teamviewer", "anydesk",
]

# Un mot de moins de 4 lettres rend le ratio de ressemblance peu significatif
# (ex. "le" vs "la" seraient déjà à 50 % de similarité pour 2 caractères) —
# exclu de la comparaison.
_WORD_PATTERN = re.compile(r"[^\W\d_]{4,}", re.UNICODE)


def _strip_accents(word: str) -> str:
    """Retire les diacritiques (é → e, à → a...) pour une comparaison stable."""
    return "".join(
        c for c in unicodedata.normalize("NFD", word) if unicodedata.category(c) != "Mn"
    )


def _has_fuzzy_keyword_variant(text_lower: str) -> bool:
    """
    Vrai si au moins un mot du texte ressemble à >= 90 % à un mot-clé de
    référence SANS lui être identique — signale une déformation volontaire ou
    une faute, pas l'orthographe correcte du mot.
    """
    words = {_strip_accents(w) for w in _WORD_PATTERN.findall(text_lower)}
    for word in words:
        for reference in SPELLING_REFERENCE_WORDS:
            if word == reference:
                continue
            ratio = SequenceMatcher(None, word, reference).ratio()
            if ratio >= SPELLING_FUZZY_THRESHOLD:
                return True
    return False


def _has_fuzzy_brand_variant(text_lower: str) -> bool:
    """
    Même principe que _has_fuzzy_keyword_variant, appliqué à BRAND_FUZZY_REFERENCE
    plutôt qu'aux mots-clés génériques — repère une marque volontairement
    déformée en texte libre (ex. "0range", "Ecobnak") pour échapper à la
    comparaison exacte de BRAND_KEYWORDS. Vérifié à ce seuil (0.90) contre des
    mots français courants (ex. "organe", "grange" restent sous 0.90) pour
    limiter le risque de faux positif.
    """
    words = {_strip_accents(w) for w in _WORD_PATTERN.findall(text_lower)}
    for word in words:
        for reference in BRAND_FUZZY_REFERENCE:
            if word == reference:
                continue
            ratio = SequenceMatcher(None, word, reference).ratio()
            if ratio >= SPELLING_FUZZY_THRESHOLD:
                return True
    return False


# =============================================================================
# FONCTIONS UTILITAIRES DE RECHERCHE
# =============================================================================
def _contains_any(text_lower: str, keywords: list[str]) -> bool:
    """Vrai si au moins un mot-clé de la liste apparaît tel quel dans le texte."""
    return any(kw in text_lower for kw in keywords)


def _matches_any(text_lower: str, patterns: list[str]) -> bool:
    """Vrai si au moins une expression régulière de la liste trouve une occurrence."""
    return any(re.search(p, text_lower, re.IGNORECASE) for p in patterns)


# =============================================================================
# POINT D'ENTREE — EVALUATION D'UN TEXTE
# =============================================================================
def evaluate_text(content: str, brand_whitelisted: bool) -> list[RuleMatch]:
    """
    Applique l'ensemble des règles bilingues au texte brut soumis et retourne
    la liste des indicateurs déclenchés (motif + points).

    Parameters
    ----------
    content : str
        Le texte ou l'URL soumis par l'utilisateur, non modifié.
    brand_whitelisted : bool
        True si services.py a trouvé l'émetteur/domaine en liste blanche
        (méthode 2) — dans ce cas, l'indicateur "identité usurpée" n'est PAS
        compté pour cette occurrence (CRL-CDC-Module3-2.0 §3.2), même si une
        marque connue est mentionnée dans le texte. Les autres indicateurs
        restent évalués normalement : une communication légitime d'Orange
        peut quand même déclencher, par exemple, l'indicateur "urgence" si
        son contenu le justifie.

    Returns
    -------
    list[RuleMatch]
        Un RuleMatch par indicateur déclenché. La somme de leurs points est
        calculée par services.check_scam, pas ici — ce module reste
        volontairement ignorant des seuils de verdict (séparation des
        responsabilités avec config.py).
    """
    text_lower = content.lower()
    matches: list[RuleMatch] = []

    # --- Demande d'argent immédiate --------------------------------------
    if _matches_any(text_lower, MONEY_REQUEST_PATTERNS):
        matches.append(RuleMatch("demande d'argent", 30))

    # --- Identité usurpée (neutralisée si liste blanche) -------------------
    # Marque mentionnée exactement (BRAND_KEYWORDS) OU sous une forme
    # volontairement déformée pour échapper à la comparaison exacte
    # (_has_fuzzy_brand_variant, ex. "0range") — un seul motif, quelle que
    # soit la voie de détection.
    if not brand_whitelisted and (
        _contains_any(text_lower, BRAND_KEYWORDS) or _has_fuzzy_brand_variant(text_lower)
    ):
        matches.append(RuleMatch("identité usurpée", 30))

    # --- Promesse de gains irréalistes, + bonus montant chiffré ------------
    if _contains_any(text_lower, GAIN_KEYWORDS):
        matches.append(RuleMatch("promesse de gains irréalistes", 25))
        if re.search(CURRENCY_AMOUNT_PATTERN, text_lower, re.IGNORECASE):
            matches.append(RuleMatch("montant chiffré précis", 15))

    # --- Urgence -----------------------------------------------------------
    if _contains_any(text_lower, URGENCY_KEYWORDS):
        matches.append(RuleMatch("urgence", 20))

    # --- Lien suspect (raccourcisseur mentionné dans le texte) -------------
    if any(shortener in text_lower for shortener in LINK_SHORTENERS):
        matches.append(RuleMatch("lien suspect", 20))

    # --- Fautes d'orthographe nombreuses (motifs fixes + variantes ~90 %) ----
    if _matches_any(text_lower, SPELLING_ERROR_PATTERNS) or _has_fuzzy_keyword_variant(text_lower):
        matches.append(RuleMatch("fautes d'orthographe nombreuses", 15))

    # --- Recrutement pyramidal (nouvel indicateur, §9.2) --------------------
    if _contains_any(text_lower, PYRAMID_RECRUITMENT_KEYWORDS):
        matches.append(RuleMatch("recrutement pyramidal", 35))

    # --- Sextorsion (nouvel indicateur, §9.2) -------------------------------
    if _contains_any(text_lower, SEXTORTION_KEYWORDS):
        matches.append(RuleMatch("sextorsion", 30))

    # --- Faux remboursement mobile money (nouvel indicateur, 28/08/2026) -----
    if _contains_any(text_lower, MOBILE_MONEY_REFUND_KEYWORDS):
        matches.append(RuleMatch("faux remboursement mobile money", 30))

    # --- Arnaque sentimentale / romance scam (nouvel indicateur, 05/09/2026) -
    if _contains_any(text_lower, ROMANCE_SCAM_KEYWORDS):
        matches.append(RuleMatch("arnaque sentimentale (romance scam)", 30))

    # --- Faux support technique (nouvel indicateur, 05/09/2026) --------------
    if _contains_any(text_lower, TECH_SUPPORT_KEYWORDS):
        matches.append(RuleMatch("faux support technique", 25))

    # --- Offre trop belle ----------------------------------------------------
    if _contains_any(text_lower, OFFER_TOO_GOOD_KEYWORDS):
        matches.append(RuleMatch("offre trop belle", 15))

    # --- Demande d'informations personnelles ----------------------------------
    if _contains_any(text_lower, PERSONAL_INFO_KEYWORDS):
        matches.append(RuleMatch("demande d'informations personnelles", 15))

    # --- Lien non sécurisé mentionné en clair (http://) -----------------------
    if "http://" in text_lower:
        matches.append(RuleMatch("lien non sécurisé (http://)", 10))

    # --- Usurpation d'institution officielle (cas MINFOPRA, §9.2) -------------
    # Une institution est mentionnée ET une adresse e-mail est présente dans
    # le texte : si cette adresse ne se termine pas par un domaine officiel
    # connu (.gov.cm / gouv.cm), c'est un signal fort d'usurpation.
    if _contains_any(text_lower, INSTITUTION_KEYWORDS):
        email_match = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", text_lower)
        if email_match and not email_match.group(0).endswith((".gov.cm", "gouv.cm")):
            matches.append(RuleMatch(
                "adresse e-mail hors domaine officiel (.gov.cm)", 25
            ))

    return matches
