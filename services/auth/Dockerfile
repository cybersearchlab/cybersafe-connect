#services/Auth/Dockerfile
# =============================================================================
# CyberSafe Connect - Auth Microservice Dockerfile (Production)
# =============================================================================
#
# This Dockerfile is optimized for production deployment.
# It includes security hardening, minimal dependencies, and no development tools.
#
# =============================================================================
# DOCKER BUILD & RUN COMMANDS
# =============================================================================
#
# Build the image:
#     docker build -t cybersafe-auth:prod .
#
# Run the container:
#     docker run -d -p 8001:8001 --name auth cybersafe-auth:prod
#
# With docker-compose:
#     docker-compose up -d auth
#
# =============================================================================
# LAYER ARCHITECTURE
# =============================================================================
#
# Layer 1: Base Image         (python:3.11-slim)
# Layer 2: Working Directory  (WORKDIR /app)
# Layer 3: Python Environment (ENV variables)
# Layer 4: System Dependencies (apt-get packages)
# Layer 5: User Creation      (non-root user)
# Layer 6: Python Dependencies (requirements.txt)
# Layer 7: Application Code   (COPY . .)
# Layer 8: Permissions        (chown -R)
# Layer 9: User Switch        (USER appuser)
# Layer 10: Port & Command    (EXPOSE, CMD)
#
# =============================================================================


# =============================================================================
# LAYER 1: BASE IMAGE SELECTION
# =============================================================================
#
# Why python:3.11-slim?
# ----------------------
# • Python 3.11: Latest stable version with performance improvements.
# • slim variant: Minimal Debian-based image (smaller attack surface).
# • Reduced size: ~120MB vs ~900MB for full image.
#
# Security Considerations:
# -------------------------
# • Slim images have fewer pre-installed packages = fewer vulnerabilities.
# • Avoid alpine variants for production (compatibility issues with C extensions).
# • Regularly update to latest patch version for security fixes.
#
FROM python:3.11-slim


# =============================================================================
# LAYER 2: WORKING DIRECTORY
# =============================================================================
#
# WORKDIR sets the working directory for all subsequent commands.
# Using /app as a standard location for Python applications.
#
# Why /app?
# ---------
# • Conventional location for application code in Docker containers.
# • Separate from system directories (/usr, /etc, /var).
# • Easy to mount volumes and manage permissions.
#
WORKDIR /app


# =============================================================================
# LAYER 3: PYTHON ENVIRONMENT VARIABLES
# =============================================================================
#
# These environment variables control Python's runtime behavior.
#
# PYTHONDONTWRITEBYTECODE=1
# --------------------------
# Prevents creation of .pyc bytecode cache files.
#
# Benefits:
# ---------
# • Reduces disk usage in the container.
# • Prevents stale bytecode issues after code updates.
# • Security: Fewer files = smaller attack surface.
#
# PYTHONUNBUFFERED=1
# ------------------
# Disables Python's output buffering.
#
# Benefits:
# ---------
# • All logs are immediately sent to stdout/stderr.
# • Essential for container logging systems (ELK, Datadog, etc.).
# • Real-time debugging and monitoring.
#
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1


# =============================================================================
# LAYER 4: SYSTEM DEPENDENCIES
# =============================================================================
#
# Install operating system packages required for Python dependencies.
#
# Package            | Purpose                                      | Required By
# -------------------|----------------------------------------------|------------
# gcc                | C compiler for compiling Python extensions   | psycopg2
# build-essential    | Build tools (make, g++, etc.)               | psycopg2
# libpq-dev          | PostgreSQL client libraries and headers     | psycopg2
#
# Why these are needed:
# ----------------------
# • psycopg2-binary may not have pre-compiled wheels for all architectures.
# • When wheels are missing, pip compiles from source.
# • Compilation requires the PostgreSQL development headers.
#
# Security Considerations:
# -------------------------
# 1. Chain commands with '&&' for fail-fast behavior.
# 2. Clean apt cache to reduce image size and remove package lists.
# 3. The build tools remain in the image (could be removed with multi-stage).
# 4. For production, consider multi-stage builds to remove build tools.
#
# NOTE: This layer includes build tools (gcc, build-essential)
#          that are only needed for compilation. In a multi-stage build,
#          these would be removed from the final image.
#
RUN apt-get update && apt-get install -y \
    gcc \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*


# =============================================================================
# LAYER 5: NON-ROOT USER CREATION
# =============================================================================
#
# Running containers as root is a major security vulnerability.
# We create a dedicated user with limited permissions.
#
# Why create a non-root user?
# ----------------------------
# • Principle of Least Privilege: Only grant necessary permissions.
# • If an attacker compromises the container, they won't have root access.
# • Prevents accidental modification of system files.
# • Required by security compliance standards (PCI-DSS, HIPAA, etc.).
#
# addgroup --system appgroup
# ---------------------------
# • Creates a system group (GID < 1000 on most Linux systems).
# • System groups are used for system services, not interactive users.
# • The group will own the application files.
#
# adduser --system appuser --ingroup appgroup
# --------------------------------------------
# • Creates a system user (UID < 1000).
# • --system: No home directory, no login shell.
# • --ingroup: Adds user to the appgroup group.
# • This user will run the application.
#
# Security Considerations:
# -------------------------
# • The user has no password and cannot log in.
# • The user has minimal system permissions.
# • Files are owned by this user to prevent unauthorized access.
#
RUN addgroup --system appgroup
RUN adduser --system appuser --ingroup appgroup


# =============================================================================
# LAYER 6: PYTHON DEPENDENCIES
# =============================================================================
#
# Copy only the requirements file first for optimal caching.
#
# Optimized Docker Caching Strategy:
# -----------------------------------
# 1. COPY requirements.txt FIRST (changes less frequently).
# 2. Run pip install to install dependencies.
# 3. COPY application code AFTER (changes more frequently).
# 4. This maximizes cache reuse during development.
#
# Why this is optimal:
# --------------------
# • Docker caches each layer separately.
# • requirements.txt changes much less often than application code.
# • When requirements.txt doesn't change, Docker reuses the cached layer.
# • This saves 2-5 minutes per build.
#
# Security Considerations:
# -------------------------
# • '--no-cache-dir' prevents pip from caching downloaded packages.
# • This reduces image size by ~50-100MB.
# • Cache would store package metadata and versions (potential info leak).
# • Use a requirements.txt with pinned versions to prevent supply chain attacks.
#
COPY requirements.txt .

# Upgrade pip to latest version:
# • Fixes compatibility issues with older pip versions.
# • Includes security patches for pip itself.
#
RUN pip install --upgrade pip

# Install Python dependencies:
# • Reads from requirements.txt.
# • Uses --no-cache-dir to minimize image size.
# • Downloads packages from PyPI.
#
RUN pip install --no-cache-dir -r requirements.txt


# =============================================================================
# LAYER 7: APPLICATION CODE
# =============================================================================
#
# Copy the application source code into the container.
#
# Why this is placed AFTER dependency installation:
# ------------------------------------------------
# • Application code changes frequently (every save).
# • Dependencies change rarely (days or weeks).
# • By placing this after pip install, we preserve the cache layer.
# • This is the #1 Docker optimization technique for Python.
#
# Security Considerations:
# -------------------------
# • Ensure .dockerignore excludes sensitive files.
#   - .env files (secrets, credentials)
#   - .git directory
#   - __pycache__ directories
#   - node_modules, etc.
# • Never copy secrets into the image.
# • Use environment variables or Docker secrets for credentials.
#
COPY . .


# =============================================================================
# LAYER 8: FILE PERMISSIONS
# =============================================================================
#
# Change ownership of the /app directory to the non-root user.
#
# chown -R appuser:appgroup /app
# --------------------------------
# • -R: Recursive - applies to all files and subdirectories.
# • appuser:appgroup : User and group ownership.
# • Ensures the application user has read/write access to its own files.
#
# Why this is necessary:
# -----------------------
# • Files are initially copied as root (from the build context).
# • The application runs as appuser (non-root).
# • Without this, the application would lack permission to:
#   - Read its own code
#   - Write to log files
#   - Create temporary files
#   - Write to /app/data for persistent storage
#
# Security Considerations:
# -------------------------
# • Only grant write permissions to directories that need it.
#   - /app/data : write needed (persistent storage)
#   - /app/media : write needed (file uploads)
#   - /app/__pycache__ : no write needed (bytecode)
# • For better security, use more granular permissions with chmod.
#
RUN chown -R appuser:appgroup /app


# =============================================================================
# LAYER 9: SWITCH TO NON-ROOT USER
# =============================================================================
#
# All subsequent commands will run as appuser, not root.
#
# Why switch users at this point?
# --------------------------------
# • The USER instruction changes the user for the rest of the Dockerfile.
# • Any RUN, CMD, or ENTRYPOINT after this point runs as appuser.
# • This ensures the container runs with least privilege.
#
# Security Considerations:
# -------------------------
# • This is a critical security control.
# • If the container is compromised, the attacker has limited permissions.
# • The user cannot modify system files or install packages.
# • The user cannot access other containers' data without explicit permissions.
#
USER appuser


# =============================================================================
# LAYER 10: PORT EXPOSURE & RUNTIME COMMAND
# =============================================================================

# -----------------------------------------------------------------------------
# EXPOSE - Declare the network port
# -----------------------------------------------------------------------------
#
# This is documentation for container orchestration.
# It does NOT publish the port to the host.
#
# Port 8001: Authentication service (non-standard port).
# 
# Security Note:
# --------------
# • Non-standard port reduces automated scanning attacks.
# • In production, use a reverse proxy (nginx, Traefik) in front.
# • Restrict access with firewall rules and network policies.
#
EXPOSE 8001

# -----------------------------------------------------------------------------
# CMD - Default command executed at container startup
# -----------------------------------------------------------------------------
#
# This command runs the FastAPI application in production mode.
#
# Command breakdown:
# ------------------
# uvicorn           : ASGI server for FastAPI applications.
# app:app           : Module 'app.py', variable 'app' (FastAPI instance).
# --host 0.0.0.0    : Bind to all network interfaces.
# --port 8001       : Listen on port 8001 (must match EXPOSE).
#
# NO --reload flag:
# --------------------
# • --reload is ONLY for development.
# • In production, --reload would:
#   - Waste CPU resources watching for file changes.
#   - Cause unnecessary restarts.
#   - Be a security risk if someone can modify files.
#
# Production recommendations:
# ---------------------------
# • Use Gunicorn + Uvicorn workers for production:
#   CMD ["gunicorn", "-k", "uvicorn.workers.UvicornWorker", "app:app"]
# • Use multiple workers for concurrency.
# • Use a process manager (supervisord, systemd) for reliability.
#
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8001"]


# =============================================================================
# PRODUCTION IMPROVEMENTS (NOT IMPLEMENTED IN THIS VERSION)
# =============================================================================
#
# 1. Multi-stage build:
#    ------------------
#    Build dependencies in a build stage, copy only runtime artifacts.
#    This removes gcc, build-essential from the final image.
#
#    Example:
#    FROM python:3.11-slim AS builder
#    RUN apt-get update && apt-get install -y gcc build-essential libpq-dev
#    COPY requirements.txt .
#    RUN pip install --user --no-cache-dir -r requirements.txt
#
#    FROM python:3.11-slim
#    COPY --from=builder /root/.local /root/.local
#    # ... rest of Dockerfile
#
# 2. Health checks:
#    ---------------
#    Add HEALTHCHECK instruction for container monitoring.
#
#    HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
#      CMD curl -f http://localhost:8001/health || exit 1
#
# 3. Security scanning:
#    ------------------
#    Scan the image for vulnerabilities before deployment.
#    Tools: Trivy, Snyk, Grype, Anchore.
#
#    trivy image cybersafe-auth:prod
#
# 4. Use .dockerignore:
#    ------------------
#    Exclude unnecessary files from the build context.
#
#    .dockerignore example:
#    .env
#    .git
#    __pycache__
#    *.pyc
#    *.log
#    .pytest_cache
#    tests/
#    docs/
#
# =============================================================================
# REFERENCES
# =============================================================================
#
# Dockerfile Best Practices:
#     https://docs.docker.com/develop/dev-best-practices/
#
# FastAPI Production Deployment:
#     https://fastapi.tiangolo.com/deployment/
#
# Uvicorn Documentation:
#     https://www.uvicorn.org/
#
# Docker Security Cheat Sheet:
#     https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html
#
# =============================================================================