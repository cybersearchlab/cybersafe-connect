"""
services/scam-checker/limiter.py
================================================================================
Limitation de débit (rate limiting) — Module Scam Checker (CyberSafe Connect)
================================================================================

Instance unique de Limiter (slowapi), partagée entre app.py (qui l'enregistre
sur l'application FastAPI) et routes.py (qui l'applique route par route via
le décorateur @limiter.limit(...)).

--------------------------------------------------------------------------------
POURQUOI UN FICHIER A PART, SEPARE DE app.py ET routes.py
--------------------------------------------------------------------------------
routes.py a besoin d'importer `limiter` pour décorer ses endpoints, et app.py
a besoin d'importer `routes` pour les enregistrer. Si `limiter` était défini
dans app.py, routes.py devrait importer app.py — qui importe déjà routes.py :
un import circulaire. Un module séparé, sans dépendance vers l'un ou l'autre,
évite le problème.

--------------------------------------------------------------------------------
CONTEXTE — POURQUOI CE MODULE EXISTE ALORS QUE README ANNONCAIT DEJA
DU RATE LIMITING POUR LE MODULE AUTH
--------------------------------------------------------------------------------
Le README du projet revendiquait déjà du rate limiting (slowapi) pour le
module auth, mais aucune dépendance slowapi ni middleware de ce type n'a été
retrouvé dans son code (voir CyberSafe_Connect_Rapport_Comprehension.docx,
§3.6). Ce module implémente réellement la limitation de débit exigée par le
CDC du Scam Checker (§8, « Limitation de débit »), avec les valeurs
proposées dans CRL - CDC - Module 3 - 2.0.docx §13.3.
================================================================================
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

# key_func=get_remote_address : la limite s'applique par adresse IP, ce qui
# couvre aussi les appels non authentifiés à /scam/check (un citoyen non
# connecté n'a pas de compte à utiliser comme clé).
limiter = Limiter(key_func=get_remote_address)
