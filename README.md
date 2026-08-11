# 🛡️ CyberSafe Connect

<div align="center">

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.116.1-009688?logo=fastapi&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Enabled-2496ED?logo=docker&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)
![Security](https://img.shields.io/badge/OWASP%20API%20Top%2010-Compliant-success)

**Plateforme de cybersécurité accessible à tous les Camerounais**

[📖 Documentation](#-documentation) · [🚀 Démarrage](#-démarrage-rapide) · [📦 Modules](#-modules) · [🔐 Sécurité](#-sécurité) · [🤝 Contribution](#-contribution)

</div>

---

## 📖 À propos

**CyberSafe Connect** est une plateforme web/mobile qui rend la cybersécurité et le droit numérique accessibles à tous les Camerounais, gratuitement.

### 🎯 Notre Mission

> "Même si vous n'y connaissez rien en technologie ou en droit, vous pouvez utiliser CyberSafe Connect pour vous protéger, signaler une arnaque, ou comprendre vos droits."

### 📊 Le Constat

| Indicateur | Chiffre | Source |
|------------|---------|--------|
| Internautes au Cameroun | **12 millions** | ART 2024 |
| Abonnés mobile money | **18 millions** | ART 2024 |
| Camerounais qui ignorent les lois cyber | **70%** | Étude CRL 2025 |
| Failles de sécurité dues à l'humain | **90%** | Standards internationaux |
| Augmentation cyberattaques Afrique | **+400% en 3 ans** | Rapports mondiaux |

### 💡 Notre Solution

**CyberSafe Connect** propose 8 modules intégrés :

1. **Authentification** - Inscription, connexion, gestion des rôles
2. **Vérificateur d'arnaques** - Analyse de SMS, emails, liens suspects
3. **Signalement citoyen** - Dépôt anonyme/nominatif d'incidents
4. **Assistant IA (Chatbot)** - Réponses aux questions cybersécurité
5. **Alertes entreprises** - Veille CVE personnalisée
6. **CyberSafe Academy** - Formation en cybersécurité
7. **Interface Grand Public** - Plateforme citoyenne
8. **Interface Entreprise** - Dashboard professionnel

---

## 🏗️ Architecture

### Vue d'ensemble

```mermaid
graph TB
    subgraph "Frontend"
        PUBLIC[Interface Grand Public]
        COMPANY[Interface Entreprise]
    end

    subgraph "Microservices"
        AUTH[Auth Service<br/>Port 8001]
        SCAM[Scam Checker<br/>Port 8002]
        REPORTS[Reports Service<br/>Port 8003]
        CHATBOT[Chatbot Service<br/>Port 8004]
        ALERTS[Alerts Service<br/>Port 8005]
        ACADEMY[Academy Service<br/>Port 8006]
    end

    subgraph "Data Layer"
        PG[(PostgreSQL)]
        REDIS[(Redis Cache)]
    end

    PUBLIC --> AUTH
    PUBLIC --> SCAM
    PUBLIC --> REPORTS
    PUBLIC --> CHATBOT
    PUBLIC --> ACADEMY
    
    COMPANY --> AUTH
    COMPANY --> ALERTS
    
    AUTH --> PG
    SCAM --> PG
    REPORTS --> PG
    CHATBOT --> PG
    ALERTS --> PG
    ACADEMY --> PG
    
    AUTH --> REDIS
    ALERTS --> REDIS
