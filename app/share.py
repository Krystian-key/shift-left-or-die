import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

MAX_PASSWORD_BYTES = 72  # bcrypt limit


def generate_share_token() -> str:
    return secrets.token_urlsafe(32)


def hash_share_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def hash_share_password(password: str) -> str:
    if len(password.encode()) > MAX_PASSWORD_BYTES:
        raise ValueError(f"Password exceeds {MAX_PASSWORD_BYTES} bytes")
    return pwd_context.hash(password)


def verify_share_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def get_share_expiry() -> datetime:
    return datetime.utcnow() + timedelta(hours=24)


def is_share_expired(expires_at: datetime) -> bool:
    return datetime.utcnow() >= expires_at


def sanitize_request_path(path: str) -> str:
    if path.startswith("/share/"):
        return "/share/[REDACTED]"
    return path
