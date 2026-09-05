"""
services/scam-checker/tests/test_url_analyzer.py
================================================================================
Tests de l'analyse heuristique d'URL (méthode 4) — url_analyzer.py
================================================================================

Inclut un test de non-régression pour le bug trouvé lors de la validation
manuelle du 26/08/2026 : la détection de typosquatting ne comparait que le
nom de domaine complet, et ratait donc toute marque déformée suivie d'un
suffixe (ex. "0range-securite.cm").
================================================================================
"""

from url_analyzer import _domain_skeleton, analyze_url, is_url


def _motifs(url: str) -> list[str]:
    return [m.motif for m in analyze_url(url)]


class TestIsUrl:
    def test_plain_domain_recognized(self):
        assert is_url("eneocameroun.com")

    def test_full_url_recognized(self):
        assert is_url("https://orange.cm/promo")

    def test_free_text_not_recognized(self):
        assert not is_url("Bonjour, comment allez-vous ?")

    def test_text_containing_a_url_not_recognized_as_pure_url(self):
        # Un texte qui CONTIENT un lien reste un texte libre pour is_url —
        # c'est rules.py (méthode 1) qui repère le lien dans ce cas, pas
        # url_analyzer.py (méthode 4), réservée aux entrées 100% URL.
        assert not is_url("Cliquez ici : https://exemple.com pour en savoir plus")


class TestTyposquatting:
    def test_exact_letter_substitution_detected(self):
        # Distance 1 sur le nom de domaine complet.
        assert any("typosquatting" in m for m in _motifs("http://0range.cm"))

    def test_brand_with_suffix_detected_regression(self):
        """
        Test de non-régression : avant le correctif du 26/08/2026, ce cas
        n'était PAS détecté car seule une comparaison sur le label de domaine
        entier était effectuée ("0range-securite" vs "orange", distance 10).
        La comparaison sur le préfixe ("0range" vs "orange", distance 1)
        corrige ce cas.
        """
        motifs = _motifs("http://0range-securite.cm/verify-account-urgent")
        assert any("typosquatting" in m for m in motifs)

    def test_legitimate_brand_domain_not_flagged(self):
        assert not any("typosquatting" in m for m in _motifs("https://orange.cm"))

    def test_unrelated_domain_not_flagged(self):
        assert not any("typosquatting" in m for m in _motifs("https://wikipedia.org"))

    def test_shortener_excluded_from_typosquatting_check(self):
        # bit.ly ne doit jamais être comparé aux marques de référence — il
        # est déjà scoré par rules.py (méthode 1) sous "lien suspect".
        assert not any("typosquatting" in m for m in _motifs("http://bit.ly/orange-promo"))


class TestPunycode:
    # Ajouté suite au benchmark comparatif du 28/08/2026 (README.md, section
    # « Pistes d'enrichissement ») : un domaine homographe (ex. "аpple.com"
    # avec un "а" cyrillique) est indétectable par la comparaison de
    # typosquatting ci-dessus, qui travaille sur la chaîne affichée — le
    # navigateur/urlparse l'encode en "xn--..." (RFC 3492), c'est ce préfixe
    # qui est repéré ici.
    def test_punycode_domain_flagged(self):
        assert any("punycode" in m for m in _motifs("http://xn--pple-43d.com"))

    def test_punycode_subdomain_flagged(self):
        assert any("punycode" in m for m in _motifs("http://xn--range-2sa.faux-site.com"))

    def test_ascii_domain_not_flagged(self):
        assert not any("punycode" in m for m in _motifs("https://orange.cm"))


class TestHomoglyphSkeleton:
    # Ajouté suite à la recherche technique du 05/09/2026 sur les mécanismes
    # de détection de typosquatting au-delà de Levenshtein (voir README).
    def test_single_homoglyph_still_caught_by_typosquatting(self):
        # Régression : une seule substitution homoglyphe reste couverte par
        # la distance de Levenshtein existante (distance 1) — le squelette
        # visuel ne doit rien changer à ce cas déjà géré.
        motifs = _motifs("http://оrange.cm")  # "о" cyrillique U+043E
        assert any("typosquatting probable de orange.cm" in m for m in motifs)

    def test_multi_homoglyph_caught_only_via_skeleton(self):
        # 3 substitutions cyrilliques (е, с, о) -> distance de Levenshtein
        # = 3, hors de portée du seuil ≤2 existant. Seul le squelette visuel
        # détecte que "есоbank" est indiscernable de "ecobank" à l'œil.
        motifs = _motifs("http://есоbank.cm")
        assert any("usurpation visuelle (homoglyphes) probable de ecobank.com" in m for m in motifs)

    def test_no_double_counting_for_single_homoglyph(self):
        # Un seul motif de marque, jamais deux, même si la distance ET le
        # squelette matchent tous les deux (cas d'une seule substitution).
        motifs = _motifs("http://оrange.cm")
        brand_motifs = [m for m in motifs if "orange.cm" in m and ("typosquatting" in m or "visuelle" in m)]
        assert len(brand_motifs) == 1

    def test_visual_bigram_substitution_normalizes_identically(self):
        # "rn" et "m" doivent produire le même squelette — mécanisme testé
        # directement, aucune marque connue du projet ne contenant ce motif
        # de façon exploitable de bout en bout.
        assert _domain_skeleton("rnicrosoft") == _domain_skeleton("microsoft")

    def test_legitimate_domain_not_flagged(self):
        motifs = _motifs("https://orange.cm")
        assert not any("visuelle" in m or "typosquatting" in m for m in motifs)

    def test_unrelated_domain_not_flagged_by_skeleton(self):
        # Un domaine réellement différent ne doit jamais matcher par hasard.
        motifs = _motifs("https://wikipedia.org")
        assert not any("visuelle" in m or "typosquatting" in m for m in motifs)


class TestHttpsCheck:
    def test_http_scheme_flagged(self):
        assert any("HTTPS" in m for m in _motifs("http://exemple.com"))

    def test_https_scheme_not_flagged(self):
        assert not any("HTTPS" in m for m in _motifs("https://exemple.com"))

    def test_missing_scheme_treated_as_insecure(self):
        assert any("HTTPS" in m for m in _motifs("exemple.com"))


class TestSubdomains:
    def test_many_subdomains_flagged(self):
        motifs = _motifs("http://compte.securite.orange.faux-domaine.com")
        assert any("sous-domaines" in m for m in motifs)

    def test_normal_domain_not_flagged(self):
        motifs = _motifs("https://orange.cm")
        assert not any("sous-domaines" in m for m in motifs)


class TestLength:
    def test_long_url_flagged(self):
        long_url = "https://exemple.com/" + "a" * 60
        assert any("longueur" in m for m in _motifs(long_url))

    def test_short_url_not_flagged(self):
        assert not any("longueur" in m for m in _motifs("https://orange.cm"))


class TestIpAsHost:
    def test_raw_ipv4_flagged(self):
        assert any("adresse IP" in m for m in _motifs("http://192.168.1.1/login"))

    def test_ipv4_with_port_flagged(self):
        assert any("adresse IP" in m for m in _motifs("http://45.33.12.9:8080/verify"))

    def test_domain_name_not_flagged(self):
        assert not any("adresse IP" in m for m in _motifs("https://orange.cm"))


class TestAtSignTrick:
    def test_userinfo_trick_flagged(self):
        # Le navigateur contacte réellement "faux-site.com" — "orange.cm"
        # n'est qu'un nom d'utilisateur ignoré.
        motifs = _motifs("http://orange.cm@faux-site.com/verify")
        assert any("trompeuse" in m or "@" in m for m in motifs)

    def test_normal_url_not_flagged(self):
        motifs = _motifs("https://orange.cm/promo")
        assert not any("trompeuse" in m for m in motifs)


class TestAbusedTld:
    def test_tk_extension_flagged(self):
        assert any("extension de domaine" in m for m in _motifs("http://mon-site-promo.tk"))

    def test_ml_extension_flagged(self):
        assert any("extension de domaine" in m for m in _motifs("http://offre-speciale.ml"))

    def test_common_extension_not_flagged(self):
        assert not any("extension de domaine" in m for m in _motifs("https://orange.cm"))
