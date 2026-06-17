version: "3.9"

services:

  auth:
    build: ./modules/auth
    container_name: cybersafe-auth
    ports:
      - "8001:8001"
    volumes:
      - ./modules/auth/data:/app/data
    environment:
      - PORT=8001

  scam-checker:
    build: ./modules/scam-checker
    container_name: cybersafe-scam
    ports:
      - "8002:8002"
    environment:
      - PORT=8002

  reports:
    build: ./modules/reports
    container_name: cybersafe-reports
    ports:
      - "8003:8003"
    volumes:
      - ./modules/reports/data:/app/data
    environment:
      - PORT=8003

  chatbot:
    build: ./modules/chatbot
    container_name: cybersafe-chatbot
    ports:
      - "8004:8004"
    volumes:
      - ./modules/chatbot/app/database:/app/database
    environment:
      - PORT=8004

  alerts:
    build: ./modules/alerts
    container_name: cybersafe-alerts
    ports:
      - "8005:8005"
    volumes:
      - ./modules/alerts/data:/app/data
    environment:
      - PORT=8005

  academy:
    build: ./modules/academy
    container_name: cybersafe-academy
    ports:
      - "8006:8006"
    environment:
      - PORT=8006

  frontend:
    build: ./frontend
    container_name: cybersafe-frontend
    ports:
      - "3000:3000"
    depends_on:
      - auth
      - scam-checker
      - reports
      - chatbot
      - academy

  business-dashboard:
    build: ./frontend
    container_name: cybersafe-business
    command: npm run business
    ports:
      - "3001:3000"
    depends_on:
      - alerts

networks:
  default:
    name: cybersafe-network