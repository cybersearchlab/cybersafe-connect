# CyberSafe Connect

CyberSafe Connect is a cybersecurity platform built with a microservices architecture.

## Current Services

* Authentication Service
* Chatbot Service
* Alerts Service
* Reports Service
* Academy Service
* Scam Checker Service

## Stack

* Python 3.11
* FastAPI
* SQLAlchemy
* Docker
* JWT Authentication
* SMTP Email Verification
* PostgreSQL (production)
* SQLite (development)

## Running Development Environment

```bash
docker compose -f docker-compose.dev.yml up --build
```

## Authentication Service Features

* User Registration
* Email Verification via OTP
* JWT Access Token
* JWT Refresh Token
* Password Hashing with bcrypt
* Protected Routes
* Role Based Access Control

## Security Features

* bcrypt password hashing
* JWT token validation
* Role restriction
* OTP expiration
* Account status management
* CORS restrictions

Project under active development.
