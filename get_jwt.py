#!/usr/bin/env python3
"""Generate JWT token for Burp testing"""
import httpx
import sys

BASE_URL = "http://localhost:8000"

# Register a test user
register_payload = {
    "username": "testuser_idor",
    "email": "testidor@example.com",
    "password": "SecureP@ssword123!"
}

print("[*] Registering test user...")
try:
    resp = httpx.post(f"{BASE_URL}/auth/register", json=register_payload)
    if resp.status_code == 201:
        print(f"✅ User registered: {register_payload['username']}")
    elif resp.status_code == 400:
        print(f"⚠️  User already exists (or validation failed)")
except Exception as e:
    print(f"❌ Registration failed: {e}")
    sys.exit(1)

# Login to get JWT
login_payload = {
    "username": register_payload["username"],
    "password": register_payload["password"]
}

print("\n[*] Logging in to get JWT token...")
try:
    resp = httpx.post(f"{BASE_URL}/auth/login", json=login_payload)
    if resp.status_code == 200:
        token = resp.json()["access_token"]
        print(f"\n✅ JWT Token:\n{token}\n")
        print(f"Use in Burp: Authorization: Bearer {token}")
    else:
        print(f"❌ Login failed: {resp.status_code} {resp.text}")
        sys.exit(1)
except Exception as e:
    print(f"❌ Login failed: {e}")
    sys.exit(1)
