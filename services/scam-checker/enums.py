"""
services/scam-checker/enums.py
================================================================================
Énumérations — Module Scam Checker (CyberSafe Connect)
================================================================================

Ce module centralise toutes les valeurs fixes utilisées à travers le service
Scam Checker : types d'entrée de la base de références, statuts du cycle de
vie d'une entrée, niveaux de verdict et actions journalisées dans le journal
d'audit.

--------------------------------------------------------------------------------
POURQUOI CE FICHIER EXISTE
--------------------------------------------------------------------------------
Sans énumération centralisée, un développeur pourrait écrire "confirmed" à un
endroit et "confirmé" ou "CONFIRMED" à un autre. Ces incohérences sont
invisibles à la lecture rapide mais cassent silencieusement les comparaisons
(ex. une entrée qui ne passe jamais réellement en liste noire active parce que
la comparaison de statut échoue).

Centraliser ces valeurs ici — sur le même principe que services/auth/enums.py
— garantit une seule source de vérité, réutilisée par :

    • models.py       (colonnes typées au niveau base de données)
    • schemas.py       (validation des requêtes/réponses API)
    • services.py       (logique métier et transitions de statut)
    • rules.py       (verdict retourné au client)

================================================================================
"""

from enum import Enum


# =============================================================================
# TYPE D'ENTREE DE LA BASE DE REFERENCES
# =============================================================================
# Détermine la nature de la valeur stockée dans BlacklistEntry / WhitelistEntry.
#
# Utilisé pour :
#     • choisir la stratégie de normalisation de la valeur (ex. un numéro de
#       téléphone est normalisé différemment d'un domaine)
#     • filtrer les recherches en base (un numéro de téléphone ne doit jamais
#       être comparé à une URL)
# =============================================================================
class EntryType(str, Enum):
    phone = "phone"
    url = "url"
    domain = "domain"


# =============================================================================
# STATUT D'UNE ENTREE DE LA LISTE NOIRE
# =============================================================================
# Cycle de vie d'une entrée — volontairement réduit à 2 états depuis la
# décision du 27/08/2026 : seul un administrateur peut faire passer une
# entrée en "confirmed", il n'existe plus de confirmation automatique par
# seuil de signalements (contrairement à une version antérieure de ce
# module, où 3 signalements suffisaient à confirmer sans revue humaine).
#
#     1. pending     Signalée par au moins un citoyen (ou personne, dans le
#                     cas d'une entrée juste créée), en attente de revue
#                     administrateur — ne déclenche PAS de verdict ROUGE
#     2. confirmed     Un administrateur a validé l'entrée (après revue de
#                     signalements, OU ajout manuel direct) — déclenche un
#                     verdict ROUGE
#
# Puisqu'une entrée ne devient jamais "confirmed" sans passer par une revue
# humaine, il n'y a plus besoin d'un statut de contestation a posteriori :
# un administrateur qui retire une entrée (à tort confirmée, ou signalement
# non fondé) la supprime directement — voir services.admin_reject_entry.
# =============================================================================
class EntryStatus(str, Enum):
    pending = "pending"
    confirmed = "confirmed"


# =============================================================================
# NIVEAU DE VERDICT RETOURNE AU CITOYEN
# =============================================================================
# Barème de scoring (CRL-CDC-Module3-2.0, section 2 et 3.5) :
#
#     ROUGE     score >= 70     Arnaque probable
#     ORANGE     30 <= score < 70     Suspect
#     VERT     score < 30     Légitime
#
# Un élément confirmé en liste noire force directement ROUGE, indépendamment
# du score textuel (voir services.check_scam).
# =============================================================================
class Verdict(str, Enum):
    rouge = "ROUGE"
    orange = "ORANGE"
    vert = "VERT"


# =============================================================================
# ACTION JOURNALISEE DANS BlacklistAuditLog
# =============================================================================
# Chaque changement d'état de la base de références est tracé avec l'une de
# ces actions, pour garantir une traçabilité complète (qui, quand, pourquoi) —
# exigence de sécurité CRL-CDC-Module3-2.0 section 8, point "Traçabilité".
#
#     report     Un citoyen connecté signale une entrée (reste "pending")
#     confirm     Un administrateur valide une entrée "pending" → "confirmed"
#     manual_add     Un administrateur ajoute directement une entrée confirmée
#     reject     Un administrateur rejette/retire une entrée (signalement non
#                 fondé encore "pending", ou entrée "confirmed" à tort) —
#                 l'entrée est supprimée, seul le journal en garde la trace
# =============================================================================
class AuditAction(str, Enum):
    report = "report"
    confirm = "confirm"
    manual_add = "manual_add"
    reject = "reject"


# =============================================================================
# LANGUE DE LA REPONSE — GET/POST /scam/check
# =============================================================================
# Le moteur de règles (rules.py) DETECTE déjà les indicateurs en français ET
# en anglais quelle que soit la langue du texte soumis (critère d'acceptation
# du CDC, §7). Ceci est différent : c'est la langue dans laquelle les motifs
# et les conseils de prudence sont RETOURNES au citoyen, choisie explicitement
# par lui via un sélecteur (demande du 28/08/2026) — indépendante de la langue
# du texte qu'il a soumis.
# =============================================================================
class Language(str, Enum):
    fr = "fr"
    en = "en"
