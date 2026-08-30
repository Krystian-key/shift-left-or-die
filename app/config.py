import os
import base64
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:////tmp/vulntracker.db")

# RSA keys for RS256 JWT (asymmetric)
# Production: Load from secret manager (AWS Secrets Manager, GCP Secret Manager, Vault)
# Development: Load from .env.local (base64-encoded to handle multi-line PEM format)
APP_DIR = Path(__file__).parent

# Try to load keys from env vars (plain or base64-encoded)
PRIVATE_KEY = os.getenv("JWT_PRIVATE_KEY")
PUBLIC_KEY = os.getenv("JWT_PUBLIC_KEY")

# If not plain, try base64
if not PRIVATE_KEY:
    private_key_b64 = os.getenv("JWT_PRIVATE_KEY_B64")
    if private_key_b64:
        try:
            PRIVATE_KEY = base64.b64decode(private_key_b64).decode()
        except Exception as e:
            logger.error("Failed to decode JWT_PRIVATE_KEY_B64: %s", e)
            raise RuntimeError(f"Invalid JWT_PRIVATE_KEY_B64 encoding: {e}")

if not PUBLIC_KEY:
    public_key_b64 = os.getenv("JWT_PUBLIC_KEY_B64")
    if public_key_b64:
        try:
            PUBLIC_KEY = base64.b64decode(public_key_b64).decode()
        except Exception as e:
            logger.error("Failed to decode JWT_PUBLIC_KEY_B64: %s", e)
            raise RuntimeError(f"Invalid JWT_PUBLIC_KEY_B64 encoding: {e}")

if not PRIVATE_KEY or not PUBLIC_KEY:
    raise RuntimeError(
        "JWT keys not configured. Set one of:\n"
        "  - JWT_PRIVATE_KEY / JWT_PUBLIC_KEY (plain PEM)\n"
        "  - JWT_PRIVATE_KEY_B64 / JWT_PUBLIC_KEY_B64 (base64-encoded PEM)\n"
        "For development, load from .env.local via pytest conftest.py\n"
        "For production, load from secret manager (AWS Secrets Manager, GCP Secret Manager, Vault)"
    )

ALGORITHM = "RS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Database credentials are now part of DATABASE_URL (loaded from Kubernetes Secret)

# Internal service API key (loaded from GitHub Secrets)
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")
if not ADMIN_API_KEY:
    raise RuntimeError(
        "ADMIN_API_KEY not configured. Set in GitHub Secrets."
    )

NOTIFY_SERVICE_URL = os.getenv("NOTIFY_SERVICE_URL", "http://localhost:3001")
