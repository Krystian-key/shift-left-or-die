import os
import sys

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from database import Base, get_db  # noqa: E402
from main import app  # noqa: E402

TEST_DB_URL = "sqlite:///./test_vulntracker.db"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def register_and_login(username="alice", email="alice@example.com", password="StrongPass123!@#"):
    reg_resp = client.post("/auth/register", json={"username": username, "email": email, "password": password})
    assert reg_resp.status_code == 201, f"Register failed: {reg_resp.text}"
    resp = client.post("/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    return resp.json()["access_token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_register_user():
    resp = client.post("/auth/register", json={
        "username": "bob",
        "email": "bob@example.com",
        "password": "StrongPass123!@#",
    })
    assert resp.status_code == 201
    assert resp.json()["username"] == "bob"


def test_register_duplicate_username():
    payload = {"username": "bob", "email": "bob@example.com", "password": "StrongPass123!@#"}
    client.post("/auth/register", json=payload)
    resp = client.post("/auth/register", json={**payload, "email": "bob2@example.com"})
    assert resp.status_code == 400


def test_register_duplicate_email():
    payload = {"username": "bob", "email": "bob@example.com", "password": "StrongPass123!@#"}
    client.post("/auth/register", json=payload)
    resp = client.post("/auth/register", json={**payload, "username": "bob2"})
    assert resp.status_code == 400
    assert "Registration failed" in resp.text


def test_register_password_too_short():
    resp = client.post("/auth/register", json={
        "username": "alice",
        "email": "alice@example.com",
        "password": "Short1!@"
    })
    assert resp.status_code == 422
    assert "16 characters" in resp.text


def test_register_password_no_uppercase():
    resp = client.post("/auth/register", json={
        "username": "alice",
        "email": "alice@example.com",
        "password": "weakpass123456!@"
    })
    assert resp.status_code == 422
    assert "uppercase" in resp.text


def test_register_password_no_lowercase():
    resp = client.post("/auth/register", json={
        "username": "alice",
        "email": "alice@example.com",
        "password": "WEAKPASS123456!@"
    })
    assert resp.status_code == 422
    assert "lowercase" in resp.text


def test_register_password_no_digit():
    resp = client.post("/auth/register", json={
        "username": "alice",
        "email": "alice@example.com",
        "password": "WeakPassword!@#$%"
    })
    assert resp.status_code == 422
    assert "digit" in resp.text


def test_register_password_no_special():
    resp = client.post("/auth/register", json={
        "username": "alice",
        "email": "alice@example.com",
        "password": "WeakPassword123456"
    })
    assert resp.status_code == 422
    assert "special character" in resp.text


def test_register_password_strong():
    resp = client.post("/auth/register", json={
        "username": "alice",
        "email": "alice@example.com",
        "password": "StrongPass123!@#"
    })
    assert resp.status_code == 201
    assert resp.json()["username"] == "alice"


def test_login_success():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "StrongPass123!@#"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "StrongPass123!@#"})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_login_wrong_password():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "StrongPass123!@#"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert resp.status_code == 401


def test_create_scan():
    token = register_and_login()
    resp = client.post("/scans", json={
        "title": "Reflected XSS in search",
        "description": "User input is echoed without sanitisation",
        "severity": "high",
        "affected_component": "GET /search",
    }, headers=auth_headers(token))
    assert resp.status_code == 201
    assert resp.json()["title"] == "Reflected XSS in search"


def test_list_scans():
    token = register_and_login()
    client.post("/scans", json={
        "title": "Test finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token))
    resp = client.get("/scans", headers=auth_headers(token))
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_search_scans():
    # TODO: add assertions for search results
    token = register_and_login()
    client.post("/scans", json={
        "title": "SQL Injection via login",
        "severity": "critical",
        "affected_component": "POST /auth/login",
    }, headers=auth_headers(token))
    resp = client.get("/scans/search?q=SQL", headers=auth_headers(token))
    assert resp.status_code == 200


def test_update_scan_status():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Open redirect",
        "severity": "medium",
        "affected_component": "redirect handler",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.patch(f"/scans/{scan_id}", json={"status": "in_progress"}, headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["status"] == "in_progress"


def test_delete_scan():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Stale finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.delete(f"/scans/{scan_id}", headers=auth_headers(token))
    assert resp.status_code == 204


# ---------------------------------------------------------------------------
# Share tests
# ---------------------------------------------------------------------------

def test_create_share_authenticated_owner_can_share():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Critical finding",
        "severity": "critical",
        "affected_component": "auth",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(token))
    assert resp.status_code == 201
    data = resp.json()
    assert "share_url" in data
    assert data["share_url"].startswith("http://localhost:8000/share/")


def test_create_share_unauthenticated_cannot_share():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Finding",
        "severity": "high",
        "affected_component": "misc",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.post(f"/scans/{scan_id}/share", json={})
    assert resp.status_code == 403


def test_create_share_user_cannot_share_another_users_scan():
    alice_pass = "AliceXPass123!@##"
    bob_pass = "BobXPass123!@#$$"
    alice_token = register_and_login("alice", "alice2@example.com", alice_pass)
    bob_token = register_and_login("bob", "bob2@example.com", bob_pass)

    scan_id = client.post("/scans", json={
        "title": "Alice's finding",
        "severity": "high",
        "affected_component": "auth",
    }, headers=auth_headers(alice_token)).json()["id"]

    resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(bob_token))
    assert resp.status_code == 404


def test_create_share_nonexistent_scan_returns_404():
    token = register_and_login()
    resp = client.post("/scans/99999/share", json={}, headers=auth_headers(token))
    assert resp.status_code == 404


def test_get_share_public_access_no_password():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Public finding",
        "severity": "high",
        "affected_component": "API",
    }, headers=auth_headers(token)).json()["id"]

    share_resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(token))
    share_url = share_resp.json()["share_url"]
    token_from_url = share_url.split("/share/")[1]

    resp = client.get(f"/share/{token_from_url}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["title"] == "Public finding"
    assert data["severity"] == "high"
    assert "owner_id" not in data
    assert resp.headers["Cache-Control"] == "no-store"
    assert resp.headers["Referrer-Policy"] == "no-referrer"


def test_get_share_password_protected_missing_password_fails():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Protected finding",
        "severity": "critical",
        "affected_component": "admin",
    }, headers=auth_headers(token)).json()["id"]

    share_resp = client.post(f"/scans/{scan_id}/share", json={"password": "secret123"}, headers=auth_headers(token))
    share_url = share_resp.json()["share_url"]
    token_from_url = share_url.split("/share/")[1]

    resp = client.get(f"/share/{token_from_url}")
    assert resp.status_code == 401
    assert "Access denied" in resp.text
    assert resp.headers["Cache-Control"] == "no-store"
    assert resp.headers["Referrer-Policy"] == "no-referrer"


def test_get_share_password_protected_incorrect_password_fails():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Protected finding",
        "severity": "critical",
        "affected_component": "admin",
    }, headers=auth_headers(token)).json()["id"]

    share_resp = client.post(f"/scans/{scan_id}/share", json={"password": "secret123"}, headers=auth_headers(token))
    share_url = share_resp.json()["share_url"]
    token_from_url = share_url.split("/share/")[1]

    resp = client.get(f"/share/{token_from_url}?password=wrongpassword")
    assert resp.status_code == 401
    assert "Access denied" in resp.text
    assert resp.headers["Cache-Control"] == "no-store"
    assert resp.headers["Referrer-Policy"] == "no-referrer"


def test_get_share_password_protected_correct_password_succeeds():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Protected finding",
        "severity": "critical",
        "affected_component": "admin",
    }, headers=auth_headers(token)).json()["id"]

    share_resp = client.post(f"/scans/{scan_id}/share", json={"password": "secret123"}, headers=auth_headers(token))
    share_url = share_resp.json()["share_url"]
    token_from_url = share_url.split("/share/")[1]

    resp = client.get(f"/share/{token_from_url}?password=secret123")
    assert resp.status_code == 200
    assert resp.json()["title"] == "Protected finding"


def test_get_share_unknown_token_returns_404():
    resp = client.get("/share/unknown_token_that_does_not_exist")
    assert resp.status_code == 404
    assert "Share link not found or expired" in resp.text


def test_get_share_excessive_token_size_returns_404():
    huge_token = "a" * 1000
    resp = client.get(f"/share/{huge_token}")
    assert resp.status_code == 404


def test_share_does_not_store_raw_token():
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
    from models import ScanShare

    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Finding",
        "severity": "high",
        "affected_component": "misc",
    }, headers=auth_headers(token)).json()["id"]

    share_resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(token))
    raw_token = share_resp.json()["share_url"].split("/share/")[1]

    db = TestingSessionLocal()
    share = db.query(ScanShare).first()
    assert share is not None
    assert share.token_hash != raw_token
    assert len(share.token_hash) == 64
    db.close()


def test_share_password_not_stored_plaintext():
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
    from models import ScanShare

    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Finding",
        "severity": "high",
        "affected_component": "misc",
    }, headers=auth_headers(token)).json()["id"]

    password = "my_secret_password"
    client.post(f"/scans/{scan_id}/share", json={"password": password}, headers=auth_headers(token))

    db = TestingSessionLocal()
    share = db.query(ScanShare).first()
    assert share.password_hash is not None
    assert share.password_hash != password
    assert share.password_hash.startswith("$2b$")
    db.close()


def test_share_expires_after_24_hours():
    from datetime import timedelta
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
    from models import ScanShare

    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Finding",
        "severity": "high",
        "affected_component": "misc",
    }, headers=auth_headers(token)).json()["id"]

    share_resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(token))
    share_url = share_resp.json()["share_url"]
    token_from_url = share_url.split("/share/")[1]

    resp = client.get(f"/share/{token_from_url}")
    assert resp.status_code == 200

    db = TestingSessionLocal()
    share = db.query(ScanShare).first()
    share.expires_at = share.created_at
    db.commit()
    db.close()

    resp = client.get(f"/share/{token_from_url}")
    assert resp.status_code == 404


def test_share_referencing_deleted_scan_fails():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Finding",
        "severity": "high",
        "affected_component": "misc",
    }, headers=auth_headers(token)).json()["id"]

    share_resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(token))
    share_url = share_resp.json()["share_url"]
    token_from_url = share_url.split("/share/")[1]

    client.delete(f"/scans/{scan_id}", headers=auth_headers(token))

    resp = client.get(f"/share/{token_from_url}")
    assert resp.status_code == 404


def test_shared_scan_excludes_owner_id():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Finding",
        "severity": "high",
        "affected_component": "misc",
    }, headers=auth_headers(token)).json()["id"]

    share_resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(token))
    share_url = share_resp.json()["share_url"]
    token_from_url = share_url.split("/share/")[1]

    resp = client.get(f"/share/{token_from_url}")
    data = resp.json()
    assert "owner_id" not in data
    assert "owner" not in data


def test_share_password_exceeds_bcrypt_limit_rejected():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Finding",
        "severity": "high",
        "affected_component": "misc",
    }, headers=auth_headers(token)).json()["id"]

    oversized_password = "a" * 100
    resp = client.post(f"/scans/{scan_id}/share", json={"password": oversized_password}, headers=auth_headers(token))
    assert resp.status_code == 422
    assert "72 bytes" in resp.text or "exceeds" in resp.text


# =========================================================================
# SECURITY FUNCTIONAL TESTS - Task 3 Remediations
# =========================================================================

def test_sql_injection_payload_rejected():
    """SQL Injection fix: Verify ' OR '1'='1 payload returns 0 results"""
    token = register_and_login()

    # Create a test scan
    client.post("/scans", json={
        "title": "SQL Test",
        "severity": "high",
        "affected_component": "Database",
    }, headers=auth_headers(token))

    # Try SQL injection payload
    resp = client.get("/scans/search?q=' OR '1'='1", headers=auth_headers(token))
    assert resp.status_code == 200
    # Payload treated as literal search term, should find 0 results
    assert resp.json()["count"] == 0
    assert resp.json()["results"] == []


def test_idor_get_scan_different_user_forbidden():
    """IDOR fix: User cannot read another user's scan via GET /scans/{scan_id}"""
    # User A creates a scan
    token_a = register_and_login(username="alice", email="alice@example.com", password="AlicePass123!@#")
    scan_resp = client.post("/scans", json={
        "title": "Alice's Secret Scan",
        "severity": "critical",
        "affected_component": "Backend",
    }, headers=auth_headers(token_a))
    scan_id = scan_resp.json()["id"]

    # User B tries to access User A's scan
    token_b = register_and_login(username="bob", email="bob@example.com", password="BobPass123!@#")
    resp = client.get(f"/scans/{scan_id}", headers=auth_headers(token_b))
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_share_password_minimum_length_enforced():
    """Share password fix: Passwords < 12 characters rejected"""
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Share Test",
        "severity": "high",
        "affected_component": "API",
    }, headers=auth_headers(token)).json()["id"]

    # Try password with only 8 characters (< minimum 12)
    resp = client.post(f"/scans/{scan_id}/share", json={"password": "Pass12!!"}, headers=auth_headers(token))
    assert resp.status_code == 422
    assert "12 characters" in resp.text


def test_share_password_complexity_uppercase_required():
    """Share password fix: Password must contain uppercase"""
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Share Test",
        "severity": "high",
        "affected_component": "API",
    }, headers=auth_headers(token)).json()["id"]

    # No uppercase (fails complexity)
    resp = client.post(f"/scans/{scan_id}/share", json={"password": "lowercase123!!"}, headers=auth_headers(token))
    assert resp.status_code == 422
    assert "uppercase" in resp.text.lower()


def test_share_password_complexity_lowercase_required():
    """Share password fix: Password must contain lowercase"""
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Share Test",
        "severity": "high",
        "affected_component": "API",
    }, headers=auth_headers(token)).json()["id"]

    # No lowercase (fails complexity)
    resp = client.post(f"/scans/{scan_id}/share", json={"password": "UPPERCASE123!!"}, headers=auth_headers(token))
    assert resp.status_code == 422
    assert "lowercase" in resp.text.lower()


def test_share_password_complexity_digit_required():
    """Share password fix: Password must contain digit"""
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Share Test",
        "severity": "high",
        "affected_component": "API",
    }, headers=auth_headers(token)).json()["id"]

    # No digit (fails complexity)
    resp = client.post(f"/scans/{scan_id}/share", json={"password": "NoDigitHere!!"}, headers=auth_headers(token))
    assert resp.status_code == 422
    assert "digit" in resp.text.lower()


def test_share_password_complexity_special_required():
    """Share password fix: Password must contain special character"""
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Share Test",
        "severity": "high",
        "affected_component": "API",
    }, headers=auth_headers(token)).json()["id"]

    # No special character (fails complexity)
    resp = client.post(f"/scans/{scan_id}/share", json={"password": "NoSpecialChar123"}, headers=auth_headers(token))
    assert resp.status_code == 422
    assert "special" in resp.text.lower()


def test_share_password_valid_complexity():
    """Share password fix: Valid password with all complexity requirements accepted"""
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Share Test",
        "severity": "high",
        "affected_component": "API",
    }, headers=auth_headers(token)).json()["id"]

    # Valid password: 12+ chars, uppercase, lowercase, digit, special
    resp = client.post(f"/scans/{scan_id}/share", json={"password": "ShareLink@2024"}, headers=auth_headers(token))
    assert resp.status_code == 201
    assert "share_url" in resp.json()


def test_scan_ownership_enforced_on_get():
    """Authorization: GET /scans/{scan_id} checks owner_id"""
    token_a = register_and_login(username="alice", email="alice@example.com", password="AlicePass123!@#")
    token_b = register_and_login(username="bob", email="bob@example.com", password="BobPass123!@#")

    # User A creates scan
    scan_resp = client.post("/scans", json={
        "title": "Alice's Sensitive Data",
        "severity": "critical",
        "affected_component": "Database",
    }, headers=auth_headers(token_a))
    scan_id = scan_resp.json()["id"]

    # User A can read their own scan
    resp_a = client.get(f"/scans/{scan_id}", headers=auth_headers(token_a))
    assert resp_a.status_code == 200
    assert resp_a.json()["title"] == "Alice's Sensitive Data"

    # User B cannot read User A's scan
    resp_b = client.get(f"/scans/{scan_id}", headers=auth_headers(token_b))
    assert resp_b.status_code == 404


# =========================================================================
# FUNCTIONAL TESTS - General Application Functionality
# =========================================================================

def test_search_scans_returns_matching_results():
    """Search: Scans matching query title/description/cve are returned"""
    token = register_and_login()

    # Create test scans
    client.post("/scans", json={
        "title": "SQL Injection in Login",
        "severity": "critical",
        "affected_component": "API",
    }, headers=auth_headers(token))

    client.post("/scans", json={
        "title": "XSS in Dashboard",
        "severity": "high",
        "affected_component": "Frontend",
    }, headers=auth_headers(token))

    # Search for "SQL"
    resp = client.get("/scans/search?q=SQL", headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["count"] == 1
    assert resp.json()["results"][0]["title"] == "SQL Injection in Login"


def test_search_scans_empty_results():
    """Search: Non-matching query returns empty results"""
    token = register_and_login()

    client.post("/scans", json={
        "title": "Buffer Overflow",
        "severity": "high",
        "affected_component": "Core",
    }, headers=auth_headers(token))

    # Search for non-existent term
    resp = client.get("/scans/search?q=NonExistent", headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["count"] == 0
    assert resp.json()["results"] == []


def test_update_scan_status():
    """Update: Scan status can be changed to valid values"""
    token = register_and_login()

    scan_id = client.post("/scans", json={
        "title": "Finding",
        "severity": "high",
        "affected_component": "API",
    }, headers=auth_headers(token)).json()["id"]

    # Update status to in_progress
    resp = client.patch(f"/scans/{scan_id}", json={"status": "in_progress"}, headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["status"] == "in_progress"

    # Update to resolved
    resp = client.patch(f"/scans/{scan_id}", json={"status": "resolved"}, headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["status"] == "resolved"


def test_update_scan_invalid_status_rejected():
    """Update: Invalid status values rejected"""
    token = register_and_login()

    scan_id = client.post("/scans", json={
        "title": "Finding",
        "severity": "high",
        "affected_component": "API",
    }, headers=auth_headers(token)).json()["id"]

    # Try invalid status
    resp = client.patch(f"/scans/{scan_id}", json={"status": "invalid_status"}, headers=auth_headers(token))
    assert resp.status_code == 400
    assert "open | in_progress | resolved" in resp.text


def test_update_scan_remediation_notes():
    """Update: Remediation notes can be added to scans"""
    token = register_and_login()

    scan_id = client.post("/scans", json={
        "title": "Finding",
        "severity": "high",
        "affected_component": "API",
    }, headers=auth_headers(token)).json()["id"]

    # Add remediation notes
    resp = client.patch(f"/scans/{scan_id}", json={"remediation_notes": "Fixed in PR #123"}, headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["remediation_notes"] == "Fixed in PR #123"


def test_delete_scan():
    """Delete: Scan can be deleted and becomes inaccessible"""
    token = register_and_login()

    scan_id = client.post("/scans", json={
        "title": "Finding",
        "severity": "high",
        "affected_component": "API",
    }, headers=auth_headers(token)).json()["id"]

    # Verify scan exists
    resp = client.get(f"/scans/{scan_id}", headers=auth_headers(token))
    assert resp.status_code == 200

    # Delete scan
    resp = client.delete(f"/scans/{scan_id}", headers=auth_headers(token))
    assert resp.status_code == 204

    # Verify scan no longer accessible
    resp = client.get(f"/scans/{scan_id}", headers=auth_headers(token))
    assert resp.status_code == 404


def test_list_scans_pagination():
    """List: Scans are returned with skip/limit pagination"""
    token = register_and_login()

    # Create 5 scans
    for i in range(5):
        client.post("/scans", json={
            "title": f"Finding {i}",
            "severity": "high",
            "affected_component": "API",
        }, headers=auth_headers(token))

    # Get first 2
    resp = client.get("/scans?skip=0&limit=2", headers=auth_headers(token))
    assert resp.status_code == 200
    assert len(resp.json()) == 2

    # Get next 2
    resp = client.get("/scans?skip=2&limit=2", headers=auth_headers(token))
    assert resp.status_code == 200
    assert len(resp.json()) == 2

    # Get remaining
    resp = client.get("/scans?skip=4&limit=10", headers=auth_headers(token))
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_share_link_access_after_deletion():
    """Share: Share link returns 404 if parent scan is deleted"""
    token = register_and_login()

    scan_id = client.post("/scans", json={
        "title": "Finding",
        "severity": "high",
        "affected_component": "API",
    }, headers=auth_headers(token)).json()["id"]

    # Create share
    share_resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(token))
    share_url = share_resp.json()["share_url"]
    token_from_url = share_url.split("/share/")[1]

    # Verify share accessible
    resp = client.get(f"/share/{token_from_url}")
    assert resp.status_code == 200

    # Delete parent scan
    client.delete(f"/scans/{scan_id}", headers=auth_headers(token))

    # Verify share no longer accessible
    resp = client.get(f"/share/{token_from_url}")
    assert resp.status_code == 404


def test_share_password_at_bcrypt_limit_accepted():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Finding",
        "severity": "high",
        "affected_component": "misc",
    }, headers=auth_headers(token)).json()["id"]

    exact_limit_password = "x" * 72
    resp = client.post(f"/scans/{scan_id}/share", json={"password": exact_limit_password}, headers=auth_headers(token))
    assert resp.status_code == 201
    assert "share_url" in resp.json()
