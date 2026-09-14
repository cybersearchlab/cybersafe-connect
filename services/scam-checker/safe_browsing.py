"""
services/scam-checker/safe_browsing.py
================================================================================
Méthode 5 (optionnelle) — Vérification externe via Google Safe Browsing
================================================================================

Écart assumé et documenté vis-à-vis du CDC (CRL-CDC-Module3-2.0, §10, « Exclus
v1 » : « Appels à des API externes de réputation (Google Safe Browsing,
VirusTotal) »). Décision du 14/09/2026 (demande explicite du porteur de
projet) : le moteur de règles seul, aussi enrichi soit-il, ne peut jamais
détecter un site de phishing tout juste créé et jamais vu par personne, ni
recouper une menace déjà confirmée à l'échelle mondiale — seule une base de
menaces externe le peut.

--------------------------------------------------------------------------------
POURQUOI CETTE API NE VIOLE PAS LE PRINCIPE ANTI-SSRF DU MODULE
--------------------------------------------------------------------------------
La règle de sécurité d'origine (§8, « absence de requête vers l'URL cible »)
visait un risque précis : suivre/rendre le contenu d'un lien fourni par un
inconnu, ce qui exposerait le service à une SSRF (le lien pointant en réalité
vers une ressource interne au réseau). L'API Safe Browsing ne fait PAS cela :
elle ne contacte JAMAIS le site cible. Le service n'envoie l'URL soumise qu'à
l'API Google elle-même (`safebrowsing.googleapis.com`, un tiers de confiance,
pas le lien suspect), qui répond si cette URL apparaît dans SA base de
menaces déjà connues. Aucun contenu du lien suspect n'est jamais chargé ni
exécuté par ce service.

--------------------------------------------------------------------------------
CE QUE CE COMPROMIS SACRIFIE, EN TOUTE TRANSPARENCE
--------------------------------------------------------------------------------
    • Confidentialité partielle : contrairement au reste du module (aucune
      donnée soumise n'est jamais transmise à un tiers), l'URL soumise par le
      citoyen EST transmise à Google lors de cette vérification — l'API
      "Lookup" utilisée ici (v4, la plus simple à intégrer) envoie l'URL
      complète, pas seulement une empreinte (contrairement au protocole
      "Update" par préfixes de hash, plus privé mais bien plus complexe à
      implémenter — voir la note technique du 05/09/2026 pour le détail du
      protocole par préfixes). Documenté ici pour rester honnête ; à
      reconsidérer si la confidentialité totale redevient prioritaire.
    • Dépendance externe : si Google Safe Browsing est indisponible ou lent,
      le service DOIT continuer à fonctionner (voir "fail open" ci-dessous) —
      jamais bloquer une vérification citoyenne pour une panne tierce.
    • Le service reste gratuit : le niveau d'usage de ce module est très en
      dessous des quotas gratuits de l'API (10 000 requêtes/jour au moment de
      l'intégration) — à surveiller si l'usage grossit fortement.

--------------------------------------------------------------------------------
FAIL OPEN — JAMAIS DE BLOCAGE SUR UNE PANNE TIERCE
--------------------------------------------------------------------------------
Si la clé API n'est pas configurée, si l'appel échoue, expire (timeout court
volontaire) ou renvoie une erreur : la fonction retourne None (« impossible à
vérifier »), jamais une exception qui remonterait jusqu'au citoyen. Le reste
du moteur de détection (règles + liste noire/blanche + heuristique d'URL)
continue de fonctionner normalement dans tous les cas.
================================================================================
"""

import logging

import httpx

from config import SAFE_BROWSING_API_KEY

logger = logging.getLogger(__name__)

_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# Délai volontairement court : une vérification citoyenne doit rester rapide
# (critère d'acceptation CDC §6, « moins de 2 secondes ») — mieux vaut
# renoncer à ce signal externe que de faire attendre le citoyen.
_TIMEOUT_SECONDS = 3.0

_THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",  # phishing
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]


def check_url_safe_browsing(url: str) -> bool | None:
    """
    Interroge l'API Google Safe Browsing (v4, méthode Lookup) pour savoir si
    l'URL soumise est déjà répertoriée comme menace confirmée.

    Retourne :
        True   si l'URL correspond à une menace connue (phishing/malware...)
        False  si l'URL est interrogée avec succès et n'apparaît dans aucune
               liste de menaces
        None   si la vérification n'a pas pu être effectuée (clé absente,
               erreur réseau, timeout, réponse invalide) — jamais traité
               comme une confirmation ni comme une infirmation de menace,
               voir services.check_scam qui ignore ce cas silencieusement.
    """
    if not SAFE_BROWSING_API_KEY:
        return None

    payload = {
        "client": {"clientId": "cybersafe-connect", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": _THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = httpx.post(
            _ENDPOINT,
            params={"key": SAFE_BROWSING_API_KEY},
            json=payload,
            timeout=_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        logger.warning("Safe Browsing indisponible (%s) — poursuite sans ce signal", exc)
        return None

    try:
        data = response.json()
    except ValueError:
        logger.warning("Safe Browsing : réponse non-JSON inattendue — poursuite sans ce signal")
        return None

    # L'API renvoie {} (objet vide) quand aucune menace n'est trouvée — sa
    # présence d'une clé "matches" non vide signale une menace confirmée.
    return bool(data.get("matches"))
