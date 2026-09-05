# Scam Checker — CyberSafe Connect

Module 2/3 (Vérificateur d'arnaques) de CyberSafe Connect. Analyse un texte
(SMS, email, WhatsApp) ou une URL et retourne un verdict de risque —
**ROUGE / ORANGE / VERT** — accompagné des motifs détectés et de conseils de
prudence.

Cahier des charges : `CRL - CDC - Module 3 - 2.0.docx` (Bureau).

## Port

`8002`

## Les 4 méthodes de détection

1. **Moteur de règles bilingue** (FR/EN) — `rules.py`
2. **Base de références** (liste noire + liste blanche) — `models.py` / `services.py`
3. **Signalement, confirmation/rejet admin** + journal d'audit — `services.py`
4. **Analyse heuristique de l'URL** — `url_analyzer.py`

**Langue de sortie du verdict** (28/08/2026) : `POST /scam/check` accepte un
champ optionnel `lang` (`"fr"` par défaut, ou `"en"`) — ne change que la
langue des motifs et conseils retournés, jamais la détection elle-même
(bilingue en entrée quel que soit ce paramètre, voir `rules.py`). Sélecteur
FR/EN visible sur la page `/scam-checker` du frontend.

**Détection approfondie** (05/09/2026) — nouvelles catégories et heuristiques :
- `rules.py` : **arnaque sentimentale / romance scam** (+30, colis bloqué en
  douane, mission militaire empêchant une rencontre, demande de carte
  cadeau — vide de couverture identifié lors du benchmark du 28/08), **faux
  support technique** (+25, virus/support Microsoft/TeamViewer), et
  **détection floue des marques** (extension du mécanisme déjà utilisé pour
  les fautes d'orthographe — ressemblance ≥90 % — aux noms de marque en
  texte libre, ex. "0range", "Orang").
- `url_analyzer.py` : **adresse IP utilisée comme domaine** (+20),
  **piège "@" dans l'URL** (+25, l'hôte réel est celui après le "@"),
  **extension de domaine gratuite très abusée** (+15, `.tk`/`.ml`/`.ga`/`.cf`).

**Détection avancée du typosquatting + anti-brigading** (05/09/2026, suite à
une recherche technique sur le fonctionnement interne de Google Safe
Browsing, PhishTank, Truecaller, ScamAdviser, Community Notes et la
littérature académique sur les homoglyphes — voir section suivante) :
- `url_analyzer.py` : **squelette visuel** (`_domain_skeleton`) — un domaine
  imitant une marque via des homoglyphes cyrilliques/grecs (ex. "есоbank"
  avec des lettres cyrilliques) ou des substitutions visuelles multi-
  caractères ("rn"→"m") est détecté même quand la distance de Levenshtein
  seule (3+ caractères différents) ne suffit plus. Un seul motif par marque,
  jamais de double comptage avec le typosquatting existant.
- `services.py` / `models.py` : **pondération anti-brigading** des
  signalements, inspirée de Truecaller — l'adresse IP de chaque signalement
  est capturée (`ScamReport.ip_address`, jamais exposée publiquement, seul
  le nombre d'IP distinctes sort de l'API) pour détecter qu'une entrée n'est
  signalée que depuis une seule origine (`low_diversity_suspected`), un
  signal complémentaire à l'étalement temporel déjà en place — purement
  indicatif pour le back-office, ne bloque jamais une confirmation admin.

  ⚠️ **Note de migration** : `ip_address` est une nouvelle colonne sur une
  table déjà existante — une base créée avant le 05/09/2026 doit être migrée
  manuellement (`ALTER TABLE scam_reports ADD COLUMN ip_address VARCHAR(45)`)
  ou supprimée pour être recréée, ce projet n'ayant pas d'outil de migration
  (Alembic) à ce stade. **En Docker (docker-compose.dev.yml)**, `/app/data`
  est un volume nommé (`scam_checker_data`), pas le dossier local
  `services/scam-checker/data/` malgré le montage bind sur `/app` — la
  commande s'exécute alors *dans le conteneur* :
  `docker exec -it cybersafe-scam-checker python -c "..."` (même script,
  chemin `/app/data/scam_checker.db`), pas sur le fichier hôte.

## Endpoints

| Endpoint | Méthode | Auth |
|---|---|---|
| `/health` | GET | Aucune |
| `/scam/check` | POST | Optionnelle |
| `/scam/report` | POST | Requise |
| `/scam/report/{report_id}/evidence` | POST | Requise (auteur) |
| `/scam/report/{report_id}/evidence` | GET | Requise (auteur) |
| `/scam/blacklist` | GET | Requise |
| `/scam/evidence/{evidence_id}/download` | GET | Requise (auteur ou admin) |
| `/scam/admin/blacklist` | POST | Admin |
| `/scam/admin/whitelist` | POST | Admin |
| `/scam/admin/confirm` | POST | Admin |
| `/scam/admin/reject` | POST | Admin |
| `/scam/admin/entries` | GET | Admin |
| `/scam/admin/entries/{entry_id}/evidence` | GET | Admin |
| `/scam/admin/audit` | GET | Admin |

Documentation interactive : `/docs` (Swagger UI).

## Lancer en local

```bash
cd services/scam-checker
cp .env.example .env   # puis aligner JWT_SECRET_KEY sur services/auth/.env
pip install -r requirements.txt
uvicorn app:app --reload --port 8002
```

## Intégration avec les autres modules

Cette branche ne contient que `services/scam-checker/` et `frontend/` — elle
ne modifie aucun fichier partagé (`docker-compose.yml`, `docker-compose.dev.yml`,
`services/auth/`...) pour rester facile à relire et à fusionner sans
conflit. Les étapes ci-dessous décrivent exactement ce qu'il faut faire
manuellement pour relier ce module au reste de la plateforme.

### 1. Module Auth — JWT partagé

Ce service **n'émet aucun token** — il valide uniquement les tokens JWT émis
par `services/auth`. Dans `services/auth/.env` et `services/scam-checker/.env`,
`JWT_SECRET_KEY` doit avoir **exactement la même valeur** dans les deux
fichiers, sans quoi toute vérification de token échoue (signature invalide).

### 2. Module Auth — créer un compte administrateur

Le rôle `admin` est volontairement bloqué à l'inscription publique
(`POST /auth/register` — voir `services/auth/schemas.py`,
`RegisterRequest.validate_role`) : n'importe qui ne doit pas pouvoir
s'auto-promouvoir admin via l'API. Le back-office de ce module
(`/scam/admin/*`) exige donc qu'un premier compte admin soit créé
directement en base, depuis le conteneur `auth` :

```bash
docker exec -it cybersafe-auth python -c "
from database import SessionLocal, Base, engine
from enums import AccountStatus, UserRole
from models import User
from security import hash_password

Base.metadata.create_all(bind=engine)
db = SessionLocal()
db.add(User(
    fullname='Administrateur Demo',
    email='admin@cybersafeconnect.cm',
    password_hash=hash_password('ChangeMoi123!'),
    role=UserRole.admin,
    is_verified=True,
    account_status=AccountStatus.active,
))
db.commit()
print('Compte admin créé')
"
```

Remplacer l'email et le mot de passe par des valeurs réelles avant tout usage
au-delà d'un test local.

### 3. Frontend

Le frontend (`frontend/`) consomme les deux API via deux variables
d'environnement :

```bash
cd frontend
cp .env.local.example .env.local
# NEXT_PUBLIC_AUTH_URL=http://localhost:8001
# NEXT_PUBLIC_SCAM_CHECKER_URL=http://localhost:8002
npm install
npm run dev
# → http://localhost:3000
```

### 4. Brancher les deux services dans docker-compose

`docker-compose.dev.yml` et `docker-compose.yml` (à la racine du dépôt) ne
connaissent pas encore `scam-checker` ni `frontend`. Ajouter les blocs
suivants sous `services:`, et une entrée dans `volumes:` en bas du fichier.

**`docker-compose.dev.yml`** — sous `services:`, à côté du bloc `auth:` :

```yaml
  scam-checker:
    build:
      context: ./services/scam-checker
      dockerfile: Dockerfile.dev
    container_name: cybersafe-scam-checker
    ports:
      - "8002:8002"
    env_file:
      - ./services/scam-checker/.env
    volumes:
      - ./services/scam-checker:/app
      - scam_checker_data:/app/data

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile.dev
    container_name: cybersafe-frontend
    ports:
      - "3000:3000"
    environment:
      - NEXT_PUBLIC_SCAM_CHECKER_URL=http://localhost:8002
    volumes:
      - ./frontend:/app
      - /app/node_modules
      - /app/.next
    depends_on:
      - scam-checker
```

Et sous `volumes:` (fin de fichier) :

```yaml
volumes:
  auth_data:
  scam_checker_data:
```

**`docker-compose.yml`** (production) — même principe, avec le `Dockerfile`
(pas `Dockerfile.dev`) et le healthcheck déjà utilisé par `auth` :

```yaml
  scam-checker:
    build:
      context: ./services/scam-checker
      dockerfile: Dockerfile
    container_name: cybersafe-scam-checker
    ports:
      - "8002:8002"
    env_file:
      - ./services/scam-checker/.env
    volumes:
      - scam_checker_data:/app/data
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8002/health')"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 15s

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    container_name: cybersafe-frontend
    ports:
      - "3000:3000"
    environment:
      - NEXT_PUBLIC_SCAM_CHECKER_URL=http://localhost:8002
    depends_on:
      - scam-checker
    restart: unless-stopped
```

Et, comme pour le fichier dev, `scam_checker_data:` sous `volumes:` en fin de
fichier.

Une fois ces blocs ajoutés :

```bash
docker-compose -f docker-compose.dev.yml up --build auth scam-checker frontend
```

### 5. Peupler la liste noire / liste blanche (optionnel)

```bash
docker exec -it cybersafe-scam-checker python seed_data.py
```

Recrée un jeu d'entrées réelles et sourcées (une escroquerie crypto confirmée
par le régulateur COSUMAF, treize domaines officiels camerounais) — sans
danger à relancer, les entrées déjà présentes sont ignorées.

## Tester le barème de scoring

```bash
python -c "
from rules import evaluate_text
matches = evaluate_text('Félicitations ! Vous avez gagné 500 000 FCFA. Contactez le 678901234 pour retirer votre gain.', brand_whitelisted=False)
print(sum(m.points for m in matches), [m.motif for m in matches])
"
```

Doit retourner un score de 70 (ROUGE).

## Écarts assumés vis-à-vis du CDC (CRL-CDC-Module3-2.0)

Le CDC d'origine (§3.3, §6, §7, §8) spécifie un mécanisme de **contestation
citoyenne** et une **confirmation automatique après un seuil de signalements
indépendants (ex. 3 comptes)**. Décision du 27/08/2026 (validée
explicitement, deux fois, par le porteur du projet) : ces deux mécanismes
sont retirés au profit d'un modèle plus simple et plus sûr — **aucune
confirmation automatique, seul un administrateur humain peut faire passer
une entrée de "pending" à "confirmed"** (voir `services.admin_confirm_entry`
/ `admin_reject_entry`, `enums.EntryStatus`).

Conséquence sur les critères d'acceptation du CDC touchant ces deux points :
ils ne sont plus applicables tels quels (il n'existe plus de statut
« contestée », ni de seuil de confirmation à dépasser). Tous les autres
critères d'acceptation du §6 restent respectés — voir la suite de tests
(`tests/test_report_admin.py`, `tests/test_check_endpoint.py`).

Justification retenue : puisqu'une entrée ne devient jamais "confirmed" sans
revue humaine, une contestation a posteriori n'a plus d'utilité — elle
existait dans le CDC d'origine spécifiquement pour corriger un effet ROUGE
déclenché automatiquement sans supervision.

## Pistes d'enrichissement (v2)

Recherche comparative menée le 28/08/2026 sur des plateformes similaires
(ScamAdviser, PhishTank, Truecaller/GetContact, Scamwatch, Action Fraud,
ReportFraud.ftc.gov, le court-code SMS 7726 au Royaume-Uni, ANTIC/CIRT-CM,
Orange Money Cameroun, Veilleurs du Web RDC) et sur la littérature
académique (détection de typosquatting, modération communautaire,
typologies de fraude mobile money en Afrique). Recommandations les plus
pertinentes, par effort croissant :

1. ✅ **Mots-clés bilingues pour le schéma « faux remboursement mobile money »**
   (« erreur de transfert », « renvoyez la différence » / « sent by
   mistake, please return ») dans `rules.py` — schéma très documenté en
   Afrique, absent du barème actuel. *Effort faible.* **Implémenté le
   28/08/2026** (`MOBILE_MONEY_REFUND_KEYWORDS`, +30 points).
2. ✅ **Détection des attaques homographes IDN/punycode** dans
   `url_analyzer.py` (préfixe `xn--`) — ferme une lacune connue de la
   détection de typosquatting par Levenshtein seul, reste purement
   structurel (aucune requête réseau). *Effort faible-moyen.* **Implémenté
   le 28/08/2026** (+20 points, faux positif assumé sur les IDN légitimes).
3. ✅ **Priorisation du signalement communautaire par étalement temporel**
   avant transmission à l'admin (sur le modèle du seuil de confirmation de
   PhishTank), sans jamais automatiser la validation. *Effort moyen.*
   **Implémenté le 28/08/2026** — `GET /scam/admin/entries` expose
   `report_spread_minutes` et `coordinated_pattern_suspected` (≥3
   signalements en moins de 5 min par défaut, `config.BURST_MIN_REPORTS` /
   `BURST_WINDOW_MINUTES`), plus un tri `?sort=reports`. Limite assumée :
   sans données de compte plus riches (ancienneté, IP — hors périmètre de ce
   service), l'étalement temporel des signalements déjà en base est le seul
   signal de diversité disponible ; reste un indice pour l'admin, jamais une
   décision automatique.
4. **Canal WhatsApp Business (bot)** en façade du moteur existant — élargit
   l'accès sans changer la logique métier. *Effort moyen.*
5. **Conseils post-verdict contextualisés** (ex. ROUGE + mobile money →
   afficher directement les canaux Orange Money/MTN et le contact CIRT-CM
   8202) au lieu d'un texte statique. *Effort moyen.*
6. **Tableau de bord public anonymisé des tendances** par catégorie
   d'arnaque, alimenté par des données déjà en base. *Effort moyen.*
7. **Partenariat USSD** avec un opérateur pour un accès sans
   smartphone/internet — gain d'accessibilité le plus important pour la
   mission du projet, mais dépend d'un accord externe. *Effort élevé.*
8. **Rôle « relais communautaire »** (association/ONG) pour signaler au nom
   de citoyens non équipés, sur le modèle Community Advocate de la FTC.
   *Effort élevé.*

Volontairement écarté (cohérence avec le périmètre v1 du CDC) : classification
ML/NLP, appels à des API de réputation payantes (Google Safe Browsing,
VirusTotal), cartographie géographique des signalements.
