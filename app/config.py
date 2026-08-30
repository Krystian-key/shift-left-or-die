import os
import base64
from pathlib import Path

DATABASE_URL = "sqlite:///./vulntracker.db"

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
        PRIVATE_KEY = base64.b64decode(private_key_b64).decode()

if not PUBLIC_KEY:
    public_key_b64 = os.getenv("JWT_PUBLIC_KEY_B64")
    if public_key_b64:
        PUBLIC_KEY = base64.b64decode(public_key_b64).decode()

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

# Database credentials (loaded from GitHub Secrets via environment variables)
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
if not DB_USER or not DB_PASSWORD:
    raise RuntimeError(
        "Database credentials not configured. Set in GitHub Secrets:\n"
        "  - DB_USER (database username)\n"
        "  - DB_PASSWORD (database password)"
    )

# Internal service API key (loaded from GitHub Secrets)
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")
if not ADMIN_API_KEY:
    raise RuntimeError(
        "ADMIN_API_KEY not configured. Set in GitHub Secrets."
    )

NOTIFY_SERVICE_URL = "http://localhost:3001"
