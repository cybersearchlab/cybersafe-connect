"""
services/scam-checker/tests/test_rules.py
================================================================================
Tests du moteur de règles bilingue (méthode 1) — rules.py
================================================================================

Couvre les 3 exemples de référence du corpus de test (CRL-CDC-Module3-2.0
§9.1), les cas réels camerounais du corpus §9.2 (MINFOPRA, recrutement
pyramidal, sextorsion), et la couverture bilingue FR/EN exigée par le
critère d'acceptation du CDC.
================================================================================
"""

from rules import evaluate_text


def _score(content: str, brand_whitelisted: bool = False) -> int:
    return sum(m.points for m in evaluate_text(content, brand_whitelisted))


def _motifs(content: str, brand_whitelisted: bool = False) -> list[str]:
    return [m.motif for m in evaluate_text(content, brand_whitelisted)]


# =============================================================================
# CORPUS DE TEST §9.1 — LES 3 EXEMPLES DE REFERENCE DU CDC
# =============================================================================
class TestReferenceCases:
    def test_rouge_case_scores_seventy(self):
        content = (
            "Félicitations ! Vous avez gagné 500 000 FCFA. "
            "Contactez le 678901234 pour retirer votre gain."
        )
        assert _score(content) == 70
        assert "demande d'argent" in _motifs(content)
        assert "promesse de gains irréalistes" in _motifs(content)

    def test_orange_case_scores_in_range(self):
        content = "Bonjour, une offre spéciale vous attend, cliquez ici : bit.ly/xyz123"
        score = _score(content)
        assert 30 <= score < 70
        assert score == 35

    def test_vert_case_scores_zero(self):
        content = (
            "Cher client, votre facture ENEO du mois d'août est disponible "
            "sur eneocameroun.com. Merci de votre confiance."
        )
        assert _score(content) == 0
        assert _motifs(content) == []


# =============================================================================
# BILINGUISME (critère d'acceptation : FR ET EN couverts dès la v1)
# =============================================================================
class TestBilingualCoverage:
    def test_english_scam_detected(self):
        content = (
            "Congratulations! You have won a lucky prize. Send money now — "
            "act now, this offer expires today."
        )
        motifs = _motifs(content)
        assert "demande d'argent" in motifs
        assert "promesse de gains irréalistes" in motifs
        assert any("urgence" in m for m in motifs)
        assert _score(content) >= 70

    def test_english_urgency_keyword(self):
        assert any("urgence" in m for m in _motifs("Act now, this offer expires today."))

    def test_english_personal_info_request(self):
        assert any(
            "informations personnelles" in m
            for m in _motifs("Please confirm your password and card number immediately.")
        )


# =============================================================================
# USURPATION DE MARQUE ET NEUTRALISATION PAR LISTE BLANCHE
# =============================================================================
class TestBrandUsurpation:
    def test_brand_mention_flagged_by_default(self):
        assert any("identité usurpée" in m for m in _motifs("Ceci est un message d'Orange Money."))

    def test_brand_mention_neutralized_when_whitelisted(self):
        motifs = _motifs("Ceci est un message d'Orange Money.", brand_whitelisted=True)
        assert not any("identité usurpée" in m for m in motifs)

    def test_other_indicators_still_apply_when_whitelisted(self):
        # brand_whitelisted ne doit neutraliser QUE l'indicateur d'usurpation,
        # pas les autres indicateurs légitimement déclenchés par le contenu.
        content = "Orange : offre spéciale, cliquez ici http://exemple.com"
        motifs = _motifs(content, brand_whitelisted=True)
        assert not any("identité usurpée" in m for m in motifs)
        assert any("offre trop belle" in m for m in motifs)


# =============================================================================
# CAS REELS CAMEROUNAIS DOCUMENTES (corpus de test §9.2)
# =============================================================================
# Contenu reconstitué à partir des faits rapportés par la presse (titre,
# dates, montants, secteurs, adresse email frauduleuse), pas du texte exact
# du message original — non disponible publiquement in extenso. Sources
# citées sur chaque cas.
# =============================================================================
class TestRealCameroonianCases:
    # --- Cas MINFOPRA — StopBlaBlaCam, 09/01/2025 ---------------------------
    # Faux communiqué daté du 30/12/2024, usurpant le MINFOPRA, annonçant un
    # "Plan d'Urgence Spécial Jeunes (PUJS) 2025" : recrutement de 6 000
    # jeunes (20-41 ans) en enseignement/santé/travaux publics/informatique/
    # agriculture, candidatures avant le 15/01/2025. Email frauduleux
    # commençant par "www", ne correspondant pas au domaine officiel .gov.cm.
    MINFOPRA_MESSAGE = (
        "MINISTÈRE DE LA FONCTION PUBLIQUE ET DE LA RÉFORME ADMINISTRATIVE "
        "(MINFOPRA) — Sur très hautes instructions du Chef de l'État, le Plan "
        "d'Urgence Spécial Jeunes (PUJS) 2025 lance un recrutement spécial de "
        "6000 jeunes Camerounais âgés de 20 à 41 ans dans les secteurs de "
        "l'enseignement, la santé, les travaux publics, l'informatique et "
        "l'agriculture. Candidatures avant le 15 janvier 2025. "
        "Contact : www.minfopragov@gmail.com"
    )

    def test_minfopra_case_flags_official_email_mismatch(self):
        motifs = _motifs(self.MINFOPRA_MESSAGE)
        assert any("domaine officiel" in m for m in motifs)

    def test_minfopra_case_flags_deadline_as_urgency(self):
        motifs = _motifs(self.MINFOPRA_MESSAGE)
        assert any("urgence" in m for m in motifs)

    def test_minfopra_case_reaches_at_least_orange(self):
        assert _score(self.MINFOPRA_MESSAGE) >= 30

    def test_institution_official_email_not_flagged(self):
        # Contre-exemple : la même institution citée, mais avec une adresse
        # réellement conforme au domaine officiel — ne doit rien déclencher.
        content = "Le MINFOPRA vous informe. Contact : recrutement@minfopra.gov.cm"
        assert not any("domaine officiel" in m for m in _motifs(content))

    # --- Cas PACD-PME — Camer.be / AllAfrica, 07/02/2026 ---------------------
    # Fausse subvention de 500 000 à 2 000 000 FCFA promise à 27 000 porteurs
    # de projet, usurpant le Programme d'Appui à la Création et au
    # Développement des PME (PACD-PME) ; le ministère confirme qu'aucun
    # programme de ce type n'était actif au moment des faits.
    PACD_PME_MESSAGE = (
        "Le Programme d'Appui à la Création et au Développement des PME "
        "(PACD-PME) offre une subvention de 500 000 à 2 000 000 FCFA à "
        "27 000 porteurs de projets. Participez au processus de sélection "
        "dès maintenant."
    )

    def test_pacd_pme_case_flags_gain_promise(self):
        # Ce cas a révélé un trou dans le barème lors de sa mise en test :
        # GAIN_KEYWORDS ne couvrait que le vocabulaire de loterie ("vous avez
        # gagné"), pas celui d'une fausse subvention institutionnelle — voir
        # rules.py, commentaire sur GAIN_KEYWORDS.
        motifs = _motifs(self.PACD_PME_MESSAGE)
        assert any("promesse de gains" in m for m in motifs)
        assert any("montant chiffré" in m for m in motifs)

    def test_pacd_pme_case_reaches_at_least_orange(self):
        assert _score(self.PACD_PME_MESSAGE) >= 30

    # --- Cas QNET / IGNITE / UNIMEC — AllAfrica, 23/06/2026 -------------------
    # Réseau de recrutement pyramidal démantelé le 22/06/2026 (13 suspects,
    # 600+ victimes identifiées) : promesses d'emplois bien rémunérés à
    # l'étranger sous couvert de marketing de réseau, victimes contraintes de
    # recruter à leur tour.
    QNET_MESSAGE = (
        "Rejoignez notre réseau de marketing et bénéficiez d'un emploi à "
        "l'étranger très rémunéré. Devenez indépendant grâce à notre réseau "
        "de distributeurs et au parrainage rémunéré."
    )

    def test_qnet_case_detected_as_pyramid_recruitment(self):
        assert any("recrutement pyramidal" in m for m in _motifs(self.QNET_MESSAGE))

    def test_qnet_case_reaches_at_least_orange(self):
        # Ce cas a également révélé un trou : à son poids initial (25 points),
        # ce message n'atteignait pas le seuil ORANGE (30) et aurait été
        # classé VERT à tort — voir rules.py, commentaire sur
        # PYRAMID_RECRUITMENT_KEYWORDS (poids relevé à 35).
        assert _score(self.QNET_MESSAGE) >= 30

    # --- Sextorsion — catégorie distincte (corpus §9.2) -----------------------
    def test_sextortion_detected_as_distinct_category(self):
        content = "Nous allons diffuser vos photos si vous ne payez pas."
        motifs = _motifs(content)
        assert any("sextorsion" in m for m in motifs)


# =============================================================================
# FAUX REMBOURSEMENT MOBILE MONEY (nouvel indicateur, benchmark 28/08/2026)
# =============================================================================
# Schéma de fraude mobile money le plus documenté en Afrique (GIABA, GSMA —
# voir README.md) : un faux SMS de transfert reçu, suivi d'une demande de
# remboursement de la « différence ».
class TestMobileMoneyRefundScam:
    def test_french_wording_detected(self):
        content = "Bonjour, j'ai fait une erreur de transfert, renvoyez la différence au 690112233 svp."
        motifs = _motifs(content)
        assert any("remboursement mobile money" in m for m in motifs)

    def test_english_wording_detected(self):
        content = "Hello, this was sent by mistake, please return the excess amount."
        motifs = _motifs(content)
        assert any("remboursement mobile money" in m for m in motifs)

    def test_unrelated_message_not_flagged(self):
        content = "Bonjour tout le monde, comment allez-vous ?"
        motifs = _motifs(content)
        assert not any("remboursement mobile money" in m for m in motifs)


# =============================================================================
# FAUTES D'ORTHOGRAPHE — VARIANTES APPROCHANTES (ressemblance >= 90 %)
# =============================================================================
class TestFuzzySpellingVariants:
    def test_deformed_keyword_detected_french(self):
        # "urgnt" ~ "urgent" (ressemblance ≈ 91 %) — déformation volontaire
        # non couverte par les motifs fixes (SPELLING_ERROR_PATTERNS).
        motifs = _motifs("Ce message est urgnt, agissez vite avant expiration.")
        assert any("orthographe" in m for m in motifs)

    def test_deformed_keyword_detected_english(self):
        # "winnner" ~ "winner" (ressemblance ≈ 92 %).
        motifs = _motifs("You are a lucky winnner, contact us today.")
        assert any("orthographe" in m for m in motifs)

    def test_correct_spelling_alone_not_flagged_as_error(self):
        # "urgent" est écrit correctement (ratio = 1.0 vs le mot de
        # référence) — ce n'est pas une faute, l'indicateur "fautes
        # d'orthographe" ne doit PAS se déclencher sur ce seul mot (il
        # déclenche en revanche bien l'indicateur "urgence", qui est distinct).
        motifs = _motifs("Ceci est urgent, merci de nous contacter rapidement.")
        assert not any("orthographe" in m for m in motifs)
        assert any("urgence" in m for m in motifs)

    def test_unrelated_clean_text_not_flagged(self):
        content = "Bonjour, comment allez-vous aujourd'hui ? Passez une bonne journée."
        assert not any("orthographe" in m for m in _motifs(content))


# =============================================================================
# ANTI DOUBLE-COMPTAGE (raccourcisseur compté une seule fois)
# =============================================================================
class TestNoDoubleCounting:
    def test_shortener_counted_once(self):
        content = "cliquez bit.ly/aaa et aussi bit.ly/bbb"
        motifs = _motifs(content)
        assert motifs.count("lien suspect") == 1

    def test_currency_bonus_only_with_gain_indicator(self):
        # Un montant chiffré seul (facture) ne doit PAS déclencher le bonus
        # "montant chiffré précis" — il n'a de sens qu'en présence d'une
        # promesse de gain (voir rules.py, commentaire sur CURRENCY_AMOUNT_PATTERN).
        content = "Votre facture de 15 000 FCFA est disponible."
        assert not any("montant chiffré" in m for m in _motifs(content))
