"""
services/scam-checker/url_analyzer.py
================================================================================
Méthode 4 — Analyse heuristique de l'URL (CRL-CDC-Module3-2.0, section 3.1)
================================================================================

Analyse la STRUCTURE d'un lien (pas son contenu). Ne s'applique que lorsque
services.py a détecté que l'entrée soumise est une URL.

--------------------------------------------------------------------------------
ROLE
--------------------------------------------------------------------------------
    • Repérer les liens raccourcis, sous-domaines suspects, absence de HTTPS
    • Repérer le typosquatting : un domaine qui imite un nom de marque connu
      avec une orthographe légèrement différente (ex. 0range.cm)
    • Repérer un encodage punycode suspect (attaque homographe IDN)
    • Repérer une adresse IP utilisée comme nom de domaine
    • Repérer le piège "@" dans une URL (hôte réel masqué après le "@")
    • Repérer une extension de domaine gratuite très majoritairement abusée
    • Repérer une longueur/complexité anormale du lien

--------------------------------------------------------------------------------
SECURITE — AUCUNE REQUETE VERS LA CIBLE
--------------------------------------------------------------------------------
Ce module n'effectue JAMAIS de requête HTTP vers le lien soumis (exigence
explicite CRL-CDC-Module3-2.0 §8, « absence de requête vers l'URL cible »).
Il ne fait qu'analyser la chaîne de caractères elle-même. C'est un choix de
sécurité délibéré : suivre un lien fourni par un utilisateur non authentifié
exposerait le service à une attaque SSRF (Server-Side Request Forgery), où le
lien pointerait en réalité vers une ressource interne au réseau de
l'entreprise plutôt que vers un site web public.

--------------------------------------------------------------------------------
PAS DE DOUBLE COMPTAGE AVEC rules.py
--------------------------------------------------------------------------------
Le raccourcisseur de lien (bit.ly, etc.) est déjà détecté et scoré par
rules.py (méthode 1, indicateur "lien suspect", +20). analyze_url() l'exclut
donc explicitement de sa propre recherche de typosquatting, pour ne jamais
attribuer deux fois des points au même indicateur.
================================================================================
"""

import re
from urllib.parse import urlparse

from rules import LINK_SHORTENERS, RuleMatch

# Reconnaît une chaîne "ressemblant à une URL", avec ou sans schéma explicite
# (http://, https://) — un utilisateur colle souvent un lien sans le préfixe.
URL_PATTERN = re.compile(
    r"^(https?://)?([\w-]+\.)+[a-z]{2,}(/\S*)?$", re.IGNORECASE
)

# Domaines officiels de référence pour la détection de typosquatting — à
# terme, cette liste devrait converger avec les entrées de type "domain" de
# la liste blanche (models.WhitelistEntry) plutôt que de rester statique ici ;
# conservée séparée pour l'instant pour ne pas coupler url_analyzer.py à une
# session de base de données.
KNOWN_BRAND_DOMAINS = [
    "orange.cm", "mtn.cm", "afrilandfirstbank.com", "ecobank.com",
    "ubagroup.com", "bicec.com", "societegenerale.cm", "eneocameroun.com",
]

# Détection d'une adresse IPv4 utilisée directement comme hôte (ex.
# "http://192.168.1.1/login") — une communication légitime destinée au grand
# public ne pointe jamais vers une IP brute, seulement vers un nom de domaine.
_IPV4_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# Extensions de domaine gratuites très majoritairement associées à des campagnes
# d'abus (phishing, spam) faute de coût d'enregistrement — un signal faible pris
# isolément, mais qui a sa place aux côtés des autres heuristiques structurelles.
_ABUSED_TLDS = {"tk", "ml", "ga", "cf"}


# =============================================================================
# DETECTION : L'ENTREE EST-ELLE UNE URL ?
# =============================================================================
def is_url(content: str) -> bool:
    """
    Détermine si le contenu soumis doit être traité comme une URL plutôt que
    comme un texte libre — décide si services.py doit appeler analyze_url()
    en complément du moteur de règles.
    """
    stripped = content.strip()
    if " " in stripped or "\n" in stripped:
        # Un texte libre contient presque toujours des espaces ; une URL seule
        # collée par l'utilisateur n'en contient jamais.
        return False
    return bool(URL_PATTERN.match(stripped))


# =============================================================================
# DISTANCE DE LEVENSHTEIN — DETECTION DE TYPOSQUATTING
# =============================================================================
def _levenshtein(a: str, b: str) -> int:
    """
    Nombre minimal de modifications (insertion/suppression/substitution d'un
    caractère) pour transformer `a` en `b`. Utilisée pour repérer un domaine
    qui ressemble fortement à une marque connue sans y correspondre
    exactement (ex. distance de 1 entre "0range" et "orange").
    """
    if len(a) < len(b):
        return _levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    previous_row = range(len(b) + 1)
    for i, ca in enumerate(a):
        current_row = [i + 1]
        for j, cb in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (ca != cb)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


# =============================================================================
# POINT D'ENTREE — ANALYSE STRUCTURELLE D'UNE URL
# =============================================================================
def analyze_url(content: str) -> list[RuleMatch]:
    """
    Analyse la structure du lien soumis (sans jamais le contacter) et retourne
    les indicateurs déclenchés. Appelée par services.check_scam uniquement
    quand is_url(content) est vrai.
    """
    matches: list[RuleMatch] = []
    stripped = content.strip()

    has_scheme = stripped.lower().startswith(("http://", "https://"))
    parsed = urlparse(stripped if has_scheme else f"http://{stripped}")
    domain = parsed.netloc.lower()

    # --- Absence de HTTPS ---------------------------------------------------
    # Un lien en http:// (ou sans schéma du tout, donc de sécurité inconnue)
    # est traité comme suspect : les sites légitimes redirigent aujourd'hui
    # systématiquement vers https://.
    if has_scheme and not stripped.lower().startswith("https://"):
        matches.append(RuleMatch("absence de HTTPS", 10))
    elif not has_scheme:
        matches.append(RuleMatch("absence de HTTPS", 10))

    # --- Sous-domaines suspects ----------------------------------------------
    # Plus de 3 segments (ex. "compte.securite.orange.faux-domaine.com") est
    # une technique courante pour donner une fausse impression de légitimité.
    labels = domain.split(".")
    if len(labels) > 3:
        matches.append(RuleMatch("sous-domaines suspects", 15))

    # --- Typosquatting d'une marque connue ------------------------------------
    # Ignore les raccourcisseurs (déjà comptés par rules.py) ; sinon compare le
    # domaine principal à chaque marque de référence par distance de
    # Levenshtein. Une distance de 1 ou 2 caractères sur un nom de marque de
    # plus de 3 lettres est considérée suspecte (au-delà, le risque de faux
    # positif entre deux noms différents devient trop élevé).
    for shortener in LINK_SHORTENERS:
        if shortener in domain:
            break
    else:
        for brand_domain in KNOWN_BRAND_DOMAINS:
            brand_root = brand_domain.split(".")[0]
            domain_root = labels[-2] if len(labels) >= 2 else domain
            if domain_root and domain_root != brand_root and len(brand_root) > 3:
                # Comparaison sur le nom complet : détecte un domaine qui
                # N'EST QUE la marque déformée (ex. "0rang3.cm").
                full_distance = _levenshtein(domain_root, brand_root)
                # Comparaison sur le préfixe de même longueur que la marque :
                # détecte une marque déformée suivie d'un suffixe quelconque
                # (ex. "0range-securite.cm", "orangepromo.cm") — sans cette
                # deuxième comparaison, seule une imitation du nom de domaine
                # ENTIER serait détectée, ce qui manque la grande majorité des
                # cas réels de typosquatting observés (voir test HTTP du
                # 26/08/2026 sur "0range-securite.cm", non détecté avant ce
                # correctif).
                prefix_distance = _levenshtein(domain_root[:len(brand_root)], brand_root)
                distance = min(full_distance, prefix_distance)
                if 0 < distance <= 2:
                    matches.append(RuleMatch(
                        f"typosquatting probable de {brand_domain}", 25
                    ))
                    break

    # --- Encodage punycode suspect (attaque homographe IDN) -------------------
    # Un domaine internationalisé (IDN) contenant des caractères non-ASCII est
    # encodé par le navigateur sous la forme "xn--..." (RFC 3492). Une attaque
    # homographe exploite ceci pour enregistrer un domaine dont l'affichage
    # imite visuellement une marque connue avec des caractères d'un autre
    # alphabet (ex. un "а" cyrillique au lieu d'un "a" latin dans "аpple.com")
    # — indétectable par la comparaison de typosquatting ci-dessus, qui
    # travaille sur la chaîne affichée et n'y verrait aucune différence.
    # Limite assumée : un IDN légitime (site multilingue non-latin) déclenche
    # aussi ce signal — un compromis documenté (benchmark 28/08/2026), au même
    # titre que les autres heuristiques structurelles de ce module.
    if any(label.startswith("xn--") for label in labels):
        matches.append(RuleMatch("encodage punycode suspect (xn--)", 20))

    # --- Adresse IP utilisée comme domaine ------------------------------------
    if parsed.hostname and _IPV4_PATTERN.match(parsed.hostname):
        matches.append(RuleMatch("adresse IP utilisée comme domaine", 20))

    # --- Piège "@" dans l'URL ---------------------------------------------------
    # "http://vrai-site.com@faux-site.com" : tout ce qui précède le "@" est
    # une simple information d'identification (nom d'utilisateur) pour le
    # navigateur — l'hôte réel contacté est "faux-site.com", après le "@".
    # Une communication légitime n'a jamais besoin d'inclure des identifiants
    # dans l'URL elle-même.
    if "@" in parsed.netloc:
        matches.append(RuleMatch("adresse trompeuse (symbole @ dans l'URL)", 25))

    # --- Extension de domaine gratuite très abusée -----------------------------
    if labels and labels[-1] in _ABUSED_TLDS:
        matches.append(RuleMatch(f"extension de domaine à risque (.{labels[-1]})", 15))

    # --- Longueur / complexité anormale ---------------------------------------
    if len(stripped) > 60:
        matches.append(RuleMatch("longueur/complexité anormale du lien", 10))

    return matches
