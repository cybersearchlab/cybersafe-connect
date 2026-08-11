# CyberSafe Connect

<div align="center">

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.116.1-009688?logo=fastapi&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Enabled-2496ED?logo=docker&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)

**Cybersecurity platform accessible to all Cameroonians**

[📖 Documentation](#-documentation) · [🚀 Quick Start](#-quick-start) · [🧪 Testing](#-testing) · [📦 Modules](#-modules) · [🔐 Security](#-security)

</div>

---

## About

**CyberSafe Connect** is a web/mobile platform that makes cybersecurity and digital law accessible to all Cameroonians, for free.

### Mission

> "Even if you know nothing about technology or law, you can use CyberSafe Connect to protect yourself, report a scam, or understand your rights."

### The Problem

| Indicator | Figure | Source |
|-----------|--------|--------|
| Internet users in Cameroon | **12 million** | ART 2024 |
| Mobile money subscribers | **18 million** | ART 2024 |
| Cameroonians unaware of cyber laws | **70%** | CRL Study 2025 |
| Security breaches due to human error | **90%** | International standards |
| Cyberattacks increase in Africa | **+400% in 3 years** | Global reports |

---

## Quick Start

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) & [Docker Compose](https://docs.docker.com/compose/install/)
- [Python 3.11+](https://www.python.org/downloads/) (for local development)
- [Git](https://git-scm.com/downloads)

### Installation

    ```bash
    # 1. Clone the repository
    git clone https://github.com/cybersearchlab/cybersafe-connect.git
    cd cybersafe-connect
    
    # 2. Copy environment files
    cp services/auth/.env.example services/auth/.env
    cp services/academy/.env.example services/academy/.env
    
    # 3. Edit configurations
    # Edit services/auth/.env
    # Edit services/academy/.env
    
# Run with Docker
    ```bash
    # Development mode - all services
    docker-compose -f docker-compose.dev.yml up --build

    # Development mode - specific service (e.g., Auth)
    docker-compose -f docker-compose.dev.yml up --build auth postgres
    
    # Production mode
    docker-compose -f docker-compose.yml up -d
    
# Local Development
    ```bash
    # Install dependencies
    cd services/auth
    pip install -r requirements.txt
    
    # Run with uvicorn
    uvicorn app:app --reload --port 8001
    
    # Or using Python
    python app.py
      
# Testing
## Test Authentication Flow (curl)
    ```bash
    # 1. Register a new user
    curl -X POST http://localhost:8001/api/v1/auth/register \
      -H "Content-Type: application/json" \
      -d '{
        "fullname": "John Doe",
        "email": "john@example.com",
        "password": "SecurePass123!",
        "role": "citizen"
      }'

    # 2. Get OTP code from logs
    docker-compose -f docker-compose.dev.yml logs auth | grep "verification code"
    
    # 3. Verify email with OTP
    curl -X POST http://localhost:8001/api/v1/auth/verify-email \
      -H "Content-Type: application/json" \
      -d '{
        "email": "john@example.com",
        "code": "123456"
      }'
    
    # 4. Login to get JWT tokens
    curl -X POST http://localhost:8001/api/v1/auth/login \
      -H "Content-Type: application/json" \
      -d '{
        "email": "john@example.com",
        "password": "SecurePass123!"
      }'
    
    # 5. Access protected endpoint
    curl -X GET http://localhost:8001/api/v1/auth/me \
      -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
    
# Test with Swagger UI
## Open your browser and navigate to:

    ```text
    http://localhost:8001/docs      # Auth Service API
    http://localhost:8006/docs      # Academy Service API
    
Click "Authorize" and enter:
    
    ```text
    Bearer YOUR_ACCESS_TOKEN
    
Then test any endpoint directly from the UI.

# Test with Python
    ```python
    import requests
    
    BASE_URL = "http://localhost:8001/api/v1/auth"
    
    # Register
    response = requests.post(
        f"{BASE_URL}/register",
        json={
            "fullname": "John Doe",
            "email": "john@example.com",
            "password": "SecurePass123!",
            "role": "citizen"
        }
    )
    print("Register:", response.json())

    # Login
    response = requests.post(
        f"{BASE_URL}/login",
        json={
            "email": "john@example.com",
            "password": "SecurePass123!"
        }
    )
    data = response.json()
    access_token = data["data"]["access_token"]
    print("Login:", access_token)
    
    # Get profile
    response = requests.get(
        f"{BASE_URL}/me",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    print("Profile:", response.json())

## Test with Postman
### 1. Import the OpenAPI spec:
  - Auth: http://localhost:8001/openapi.json
  -  Academy: http://localhost:8006/openapi.json
### 2. Create environment variables:
  - BASE_URL: http://localhost:8001
  - ACCESS_TOKEN: (set after login)
### 3. Test the flow:
 - Register → Get OTP from logs → Verify → Login → Access /me

# Modules
Module	Port	Description	Status
Auth	8001	Authentication, JWT, OTP, Email	Complete
Scam Checker	8002	Suspicious text/URL analysis	🚧 In Progress
Reports	8003	Incident reporting (anonymous/named)	🚧 In Progress
Chatbot	8004	AI assistant for cybersecurity	🚧 In Progress
Alerts	8005	CVE alerts for companies	🚧 In Progress
Academy	8006	Cybersecurity training	🚧 In Progress

# Security
## OWASP API Security Top 10 - Compliant
#	Category	Implementation
1	Broken Object Level Authorization	Role-based access control
2	Broken Authentication	JWT + Argon2 + OTP
3	Broken Object Property Level Auth	Pydantic schemas filtering
4	Unrestricted Resource Consumption	Rate Limiting + Timeout
5	Broken Function Level Authorization	Role validation
6	Unrestricted Sensitive Flows	OTP + Rate Limiting
8	Security Misconfiguration	Security Headers + CORS
9	Improper Inventory Management	Full logging + Monitoring

## Security Features
 - JWT with refresh token rotation
 - Password hashing (Argon2 production / bcrypt dev)
 - OTP email verification (15 min expiry)
 - Rate limiting (slowapi)
 - Security headers (CSP, HSTS, X-Frame-Options)
 - CORS restricted
 - TLS 1.3 for production

## Environment Variables
Auth Service - .env
    
    ```env
    # Application
    ENVIRONMENT=development
    PORT=8001
    DEBUG=true
    
    # JWT Security
    JWT_SECRET_KEY=your_very_long_secret_key_here
    ACCESS_TOKEN_EXPIRE_MINUTES=30
    REFRESH_TOKEN_EXPIRE_DAYS=7
    OTP_EXPIRE_MINUTES=15
    
    # Database
    DATABASE_URL=postgresql://postgres:postgres@postgres:5432/cybersafe_auth
    
    # SMTP Email
    SMTP_HOST=smtp.gmail.com
    SMTP_PORT=587
    SMTP_USER=your_email@gmail.com
    SMTP_PASSWORD=your_app_password
    EMAIL_FROM=your_email@gmail.com
    
    # CORS
    ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001

# Service Status
Service	Endpoint	Status	Health Check
Auth	http://localhost:8001/health	✅ Healthy	{"status":"healthy","database":"connected"}
Academy	http://localhost:8006/health	🚧 Coming Soon	-

# Documentation
## Per Service
 - Auth Service Documentation
 - Academy Service Documentation

# General
 - Architecture Overview
 - Deployment Guide
 - Security Guide
 - Contributing Guide

🤝 Contributing
Fork the project

Create a branch: git checkout -b feature/your-feature
Commit: git commit -m "feat: add your feature"
Push: git push origin feature/your-feature
Pull Request to main branch

## Guidelines
 1. PEP 8 standards
 2. Docstrings in English
 3. Unit tests
 4. Microservices architecture
 5. OWASP security principles

## Expected Impact
Objective	Target	Timeline
Citizens educated	50,000	3 years
Cybercrime reduction	30%	3 years
Reports processed	5,000/year	3 years
SMEs protected	500	3 years

## Contact
Cybersecurity Research Laboratory (CRL)
📍 Jouvence, Yaoundé, Cameroon
📞 +237 6 20 12 64 27
📧 info@cybersearchlab.com
🌐 https://www.cybersearchlab.com

📄 License
MIT © Cybersecurity Research Laboratory (CRL)

<div align="center">
⬆ Back to top

Made with ❤️ by the Cybersecurity Research Laboratory (CRL)

</div> ```
