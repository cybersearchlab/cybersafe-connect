# CyberSafe Connect — Frontend

Interface Next.js 14 (App Router) consommant les API des modules Auth
(`services/auth`, port 8001) et Scam Checker (`services/scam-checker`, port
8002) : inscription/connexion, vérification de texte/URL, signalement
citoyen avec preuves, liste noire consultable, back-office administrateur.

## Lancer en local

```bash
cd frontend
cp .env.local.example .env.local
# NEXT_PUBLIC_AUTH_URL=http://localhost:8001
# NEXT_PUBLIC_SCAM_CHECKER_URL=http://localhost:8002
npm install
npm run dev
# → http://localhost:3000
```

Nécessite que les services Auth et Scam Checker tournent déjà (voir leurs
README respectifs).

## Procédure d'intégration complète

Pour brancher ce frontend et le module Scam Checker au reste de la
plateforme (docker-compose, création d'un compte admin, JWT partagé) :
voir [`services/scam-checker/README.md`](../services/scam-checker/README.md#intégration-avec-les-autres-modules).

## Structure

```
app/
  layout.js, page.js        Nav globale, page d'accueil
  login/, register/         Authentification (module Auth)
  scam-checker/
    page.js                 Vérification + signalement citoyen
    liste/page.js            Liste noire confirmée (tout compte connecté)
    admin/page.js            Back-office (confirmer/rejeter, ajout manuel)
    i18n.js                  Traductions FR/EN partagées par ces 3 pages
lib/
  auth.js                  État d'authentification (localStorage)
  apiError.js              Normalisation des erreurs API en message affichable
```
