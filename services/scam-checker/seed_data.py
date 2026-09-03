"""
services/scam-checker/seed_data.py
================================================================================
Peuple la liste noire et la liste blanche avec des entrées réelles,
sourcées et vérifiées (recherche documentaire du 02/09/2026 — voir
README.md, section « Pistes d'enrichissement » pour la méthodologie).
================================================================================

Ces entrées n'existent que dans une base de développement locale tant que ce
script n'a pas été exécuté — elles ne sont pas incluses dans le dépôt
autrement, puisque *.db est gitignored (voir DEVELOPMENT NOTES du CDC).
Idempotent : peut être relancé sans dupliquer les entrées déjà présentes.

Usage (depuis l'intérieur du conteneur, où la base est déjà accessible) :

    docker exec -it cybersafe-scam-checker python seed_data.py

Ou en local depuis services/scam-checker/ avec les dépendances installées et
DATABASE_URL pointant vers la bonne base :

    python seed_data.py
================================================================================
"""

from database import Base, SessionLocal, engine
from enums import EntryType
from fastapi import HTTPException
from services import admin_add_blacklist_entry, admin_add_whitelist_entry

SEED_ACTOR = "seed-script"

# Source primaire : communiqué COSUMAF (régulateur financier CEMAC) n°03-21,
# juin 2021 — https://cosumaf.org/wp-content/uploads/2021/06/COMMUNIQUE-DE-PRESSE-COSUMAF-N-03-21_Mise-en-garde.pdf
# Corroboré par digitalbusiness.africa et Radio-Canada (témoignages diaspora).
BLACKLIST = [
    {
        "type": EntryType.domain,
        "value": "liyeplimal.net",
        "reason": (
            "Plateforme d'investissement crypto frauduleuse (Global Investment "
            "Trading / LimoCoin Swap, promoteur Emile Parfait Simb) - mise en "
            "garde officielle du regulateur financier CEMAC (COSUMAF), "
            "communique n.03-21 de juin 2021, plus de 300 000 victimes dont "
            "une large diaspora camerounaise."
        ),
        "description": (
            "Source primaire : communique COSUMAF (regulateur CEMAC) "
            "https://cosumaf.org/wp-content/uploads/2021/06/COMMUNIQUE-DE-PRESSE-COSUMAF-N-03-21_Mise-en-garde.pdf "
            "- corrobore par digitalbusiness.africa et Radio-Canada (temoignages diaspora)."
        ),
    },
]

# Domaines officiels vérifiés — banques, télécoms et institutions
# camerounaises, par récupération directe du site officiel ou source
# réglementaire concordante.
WHITELIST = [
    ("afrilandfirstbank.com", "Afriland First Bank"),
    ("ecobank.com", "Ecobank"),
    ("ubagroup.com", "UBA"),
    ("bicec.com", "BICEC"),
    ("societegenerale.cm", "Societe Generale Cameroun"),
    ("orange.cm", "Orange Cameroun"),
    ("orangemoney.orange.cm", "Orange Money Cameroun"),
    ("mtn.cm", "MTN Cameroun"),
    ("camtel.cm", "CAMTEL"),
    ("antic.cm", "ANTIC"),
    ("minfopra.gov.cm", "MINFOPRA"),
    ("cirt.cm", "CIRT-CM"),
    ("minpostel.gov.cm", "MINPOSTEL"),
]


def run() -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        for entry in BLACKLIST:
            admin_add_blacklist_entry(
                db, entry["type"], entry["value"], entry["reason"], SEED_ACTOR, entry["description"],
            )
            print(f"[liste noire] {entry['value']}")

        for value, brand in WHITELIST:
            try:
                admin_add_whitelist_entry(db, EntryType.domain, value, brand)
                print(f"[liste blanche] {value} ({brand})")
            except HTTPException as exc:
                if exc.status_code == 400:
                    print(f"[liste blanche] {value} — déjà présent, ignoré")
                else:
                    raise
    finally:
        db.close()


if __name__ == "__main__":
    run()
