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

# Database credentials (migrate to env vars before production deployment)
DB_USER = "vulntracker_app"
DB_PASSWORD = "Tr@cker2024!"

# Internal service API key
ADMIN_API_KEY = "sk-vt-prod-8f3a2b1c9d4e5f6a7b8c9d0e1f2a3b4c"

NOTIFY_SERVICE_URL = "http://localhost:3001"
