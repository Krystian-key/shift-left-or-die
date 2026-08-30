# Build stage: compile dependencies into system-wide location
FROM python:3.11-slim as builder

WORKDIR /build
COPY requirements.txt .

# Install to /install prefix (will be copied to /usr/local in runtime)
# This avoids PYTHONPATH issues with nonroot user home directories
# --only-binary=:all: Disallow source distributions and package build execution (PEP 517)
# NOTE: For production, add --require-hashes with valid SHA-256 in requirements.txt
RUN pip install \
    --no-cache-dir \
    --only-binary=:all: \
    --prefix=/install \
    -r requirements.txt

# Runtime stage: python:3.11-slim (minimal attack surface)
# NOTE: For production, use: gcr.io/distroless/python3.11
FROM python:3.11-slim

WORKDIR /app

# Copy Python dependencies to system location (accessible by nonroot, read-only)
# This prevents privilege escalation and ensures proper module resolution
COPY --from=builder --chown=root:root /install /usr/local

# Copy application code as root, readable by nonroot but not writable
# If RCE occurs, nonroot process can READ code but CANNOT MODIFY it
# u=rwX (root: read/write/execute), go=rX (others: read/execute only)
COPY --chown=root:root --chmod=u=rwX,go=rX app/ .

# Security context:
# - UID/GID 65532 corresponds to the Distroless 'nonroot' user
# - Application runs without root privileges
# - See: https://github.com/GoogleContainerTools/distroless#users
# - Python must handle signals properly for graceful shutdown

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER 65532:65532

# Health check using Python's urllib (no shell needed for distroless)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).read()"]

EXPOSE 8000

ENTRYPOINT ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
