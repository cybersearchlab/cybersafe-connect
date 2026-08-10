# services/academy/Dockerfile
# =============================================================================
# CyberSafe Connect - Academy Microservice Dockerfile (Production)
# =============================================================================
#
# This Dockerfile is optimized for production deployment.
# It includes persistent storage directories for data and media files.
# 
# =============================================================================
# DOCKER BUILD & RUN COMMANDS
# =============================================================================
#
# Build the image:
#     docker build -t cybersafe-academy:prod .
#
# Run the container:
#     docker run -d -p 8006:8006 --name academy cybersafe-academy:prod
#
# =============================================================================
# LAYER ARCHITECTURE
# =============================================================================
#
# Layer 1: Base Image         (python:3.11-slim)
# Layer 2: Working Directory  (WORKDIR /app)
# Layer 3: Python Environment (ENV variables)
# Layer 4: Directory Creation (mkdir -p /app/data /app/media)
# Layer 5: Python Dependencies (requirements.txt)
# Layer 6: Application Code   (COPY . .)
# Layer 7: Port & Command    (EXPOSE, CMD)
#
# SECURITY CONCERN: This Dockerfile does NOT create a non-root user.
#                      The application runs as root (highly insecure).
#
# =============================================================================


# =============================================================================
# LAYER 1: BASE IMAGE SELECTION
# =============================================================================
#
# python:3.11-slim: Minimal Python image with security benefits.
# See Auth Dockerfile for detailed explanation.
#
FROM python:3.11-slim


# =============================================================================
# LAYER 2: WORKING DIRECTORY
# =============================================================================
#
# Standard /app directory for the application code.
#
WORKDIR /app


# =============================================================================
# LAYER 3: PYTHON ENVIRONMENT VARIABLES
# =============================================================================
#
# Standard Python optimizations for containers.
#
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1


# =============================================================================
# LAYER 4: PERSISTENT STORAGE DIRECTORIES
# =============================================================================
#
# Create directories for persistent data and file uploads.
#
# /app/data  : Database files, configuration, persistent state.
# /app/media : User-uploaded files (PDFs, images, videos).
#
# Why this is needed:
# -------------------
# • The container is ephemeral - data is lost on restart.
# • These directories serve as mount points for Docker volumes.
# • Pre-creating them ensures proper permissions.
#
# Security Considerations:
# -------------------------
# • Both directories are created as root (owner is root).
# • This could be a security risk if the application runs as root.
# • In production, these should be owned by a non-root user.
# • Consider setting restrictive permissions (750 or 700).
#
RUN mkdir -p /app/data /app/media


# =============================================================================
# LAYER 5: PYTHON DEPENDENCIES
# =============================================================================
#
# Standard pip installation with cache optimization.
# See Auth Dockerfile for detailed explanation.
#
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt


# =============================================================================
# LAYER 6: APPLICATION CODE
# =============================================================================
#
# Copy all application code into the container.
#
# Security Note:
# --------------
# • Sensitive files should be excluded via .dockerignore.
# • Secrets should NOT be copied into the image.
# • Use environment variables for configuration.
#
COPY . .


# =============================================================================
# LAYER 7: PORT EXPOSURE & RUNTIME COMMAND
# =============================================================================

# -----------------------------------------------------------------------------
# EXPOSE - Declare the network port
# -----------------------------------------------------------------------------
#
# Port 8006: Academy service (non-standard port).
#
EXPOSE 8006

# -----------------------------------------------------------------------------
# CMD - Production runtime command
# -----------------------------------------------------------------------------
#
# Run with Uvicorn in production mode (NO --reload).
#
# WARNING: This runs as root (no USER instruction).
#             This is a SECURITY RISK in production.
#
# TODO: Add non-root user and user switching.
#
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8006"]


# =============================================================================
# SECURITY IMPROVEMENTS REQUIRED
# =============================================================================
#
# 1. CRITICAL: Add non-root user
#    -----------------------------
#    RUN addgroup --system appgroup
#    RUN adduser --system appuser --ingroup appgroup
#    RUN chown -R appuser:appgroup /app /app/data /app/media
#    USER appuser
#
# 2. Add system dependencies (libpq-dev) if using PostgreSQL
#    ------------------------------------
#    RUN apt-get update && apt-get install -y libpq-dev && rm -rf /var/lib/apt/lists/*
#
# 3. Use multi-stage build to remove build tools
#    -------------------------------------------
#    See Auth Dockerfile for example.
#
# 4. Add health check
#    ----------------
#    HEALTHCHECK --interval=30s --timeout=3s \
#      CMD curl -f http://localhost:8006/health || exit 1
#
# =============================================================================