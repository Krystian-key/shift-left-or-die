# Security Findings Report

## Summary

This document prioritizes security findings from automated scans (SAST, SCA) and manual testing. Findings are assessed for severity based on exploitability, business impact in the context of a vulnerability tracker, and whether they affect existing or new code.

---

## Critical Findings

### 1. SQL Injection via SQLAlchemy.text() with User Input

| Property | Value |
|----------|-------|
| **Tool & Scan Type** | Semgrep (SAST) |
| **Location** | `app/database.py:22-28` (`search_scans_by_query` function) |
| **Code** | Raw SQL with f-string interpolation: `f"SELECT ... WHERE title LIKE '%{query}%' OR description LIKE '%{query}%' OR cve_id LIKE '%{query}%'"` |
| **Severity** | **CRITICAL** |
| **CVSS Score** | 9.8 (High confidence, full database disclosure) |
| **Code Origin** | **New feature** (added in Task 1) |

**Justification:**
- The `search_scans_by_query()` function constructs SQL using f-string interpolation without parameterization
- User-controlled `q` parameter is directly embedded into SQL WHERE clauses
- SQLAlchemy's `text()` function bypasses SQL injection protections (unlike ORM operations)
- Exploitable via GET parameter: `/scans/search?q=' OR '1'='1`
- **Proof:** Successfully tested in Burp — payload returns all scans instead of filtered results

**Business Impact:**
- **Data Disclosure:** Attacker can read ALL scan records and security findings, bypassing authorization checks. This is a complete database dump.
- **Data Modification:** Using `UNION` or `INSERT/UPDATE/DELETE` payloads, attacker can modify scan records, false flagging findings as "fixed" or deleting evidence.
- **Authentication Bypass:** Scans are supposed to be isolated by `owner_id`. SQL injection allows cross-tenant access to other users' security assessments.
- **Compliance:** If this tool processes regulatory data (SOC 2, ISO 27001 compliance scans), data exfiltration violates audit requirements.

**Remediation Priority:** Fix immediately before any production deployment.

**Proof of Concept (Burp tested - 2026-08-30):**
```
Request:
GET /scans/search?q=%27%20OR%20%271%27%3D%271 HTTP/1.1
Host: localhost:8000
Authorization: Bearer <valid_jwt>

Response (HTTP 200 OK):
{
  "results": [
    {"id":"6b7349dd-b453-4205-b60b-cc435435bc56","title":"Test Report","severity":"high","status":"open","cve_id":null,"affected_component":"API Gateway",...},
    {"id":"1f621080-ecf1-4360-8a83-e996405a7b37","title":"Test Report","severity":"high","status":"open","cve_id":null,"affected_component":"API Gateway",...},
    {"id":"8fd7bf99-2d76-4b22-a20e-466e4c251d29","title":"Test Report","severity":"low","status":"open","cve_id":null,"affected_component":"API Gateway",...}
  ],
  "count": 3
}
```
**Analysis:** Payload `' OR '1'='1` successfully bypassed the SQL WHERE clause. The endpoint returned ALL scans in database (count: 3) instead of search results matching the query. Database query became: `WHERE title LIKE '%' OR '1'='1%' OR ...` which evaluates all rows to true. ✅ **EXPLOITATION CONFIRMED**

---

## High Findings

### 2. Insecure Direct Object Reference (IDOR) - Information Disclosure

| Property | Value |
|----------|-------|
| **Tool & Scan Type** | Manual code review |
| **Location** | `app/main.py:259-268` (`get_scan` function) |
| **Code** | `db.query(models.ScanResult).filter(models.ScanResult.id == scan_id).first()` — missing `owner_id` check |
| **Severity** | **HIGH** |
| **CWE** | CWE-639: Authorization Bypass Through User-Controlled Key |
| **Code Origin** | **New feature** (added in Task 1) |

**Justification:**
- GET `/scans/{scan_id}` returns scan details without verifying ownership
- Any authenticated user can enumerate and read all scans in the database by guessing/bruteforcing scan IDs (UUIDs)
- UUID format (`6b7349dd-b453-4205-b60b-cc435435bc56`) makes enumeration harder, but not impossible with 2^128 space
- Inconsistent authorization: PATCH and DELETE endpoints correctly check `owner_id`, but GET does not

**Business Impact:**
- **Data Leakage:** Attacker can read all vulnerability reports, sensitive scan findings, and remediation notes from all users
- **Competitive Intelligence:** Attacker can map out which systems other organizations have scanned and what vulnerabilities they have
- **Compliance Violation:** GDPR data isolation requirement violated — user data accessible to unauthorized users
- **Audit Trail:** Attackers can monitor scans of other users without detection

**Exploitation Example:**
```bash
# Attacker with valid JWT token can read any scan
curl -H "Authorization: Bearer <attacker_jwt>" \
  http://localhost:8000/scans/6b7349dd-b453-4205-b60b-cc435435bc56
# Returns full scan details regardless of who owns it
```

**Note on UUID Enumeration:**
- UUIDs (v4 random) are 128-bit, making brute-force enumeration impractical (2^128 possibilities)
- However, if database leaks or attacker finds scan URLs from logs/emails, they can access them
- The real risk is in the **absence of authorization check** — if UUIDs were predictable or discoverable, full IDOR would be trivial

**Context: Previous Vulnerability:**
- **Before Task 1 remediation:** User IDs and Scan report IDs used sequential Integer values (1, 2, 3, 4...)
- **Guessable paths:** Attacker could easily enumerate all scans with simple incrementing IDs: `/scans/1`, `/scans/2`, `/scans/3`
- **No JWT protection:** Endpoints were accessible without authentication or with weak token validation
- **Result:** IDOR was trivial — enumerate IDs sequentially and read any scan in database without authorization
- **Current state:** UUIDs make enumeration impractical (2^128 space), but **authorization check is still missing**, so IDOR remains viable if IDs can be discovered through other means

**Remediation:** Add `owner_id` check to GET endpoint (same as PATCH/DELETE endpoints)

**Proof of Concept (Burp tested - 2026-08-30):**
```
Scenario:
- testidor_user (attacker) has valid JWT token
- Scan 6b7349dd-b453-4205-b60b-cc435435bc56 belongs to different user

Request:
GET /scans/6b7349dd-b453-4205-b60b-cc435435bc56 HTTP/1.1
Host: localhost:8000
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0aWRvcl91c2VyIiwiZXhwIjoxNzg4MDg2MjM0fQ...

Response (HTTP 200 OK):
{
  "id": "6b7349dd-b453-4205-b60b-cc435435bc56",
  "title": "Test Report",
  "description": null,
  "severity": "high",
  "status": "open",
  "cve_id": null,
  "affected_component": "API Gateway",
  "owner_id": "ba4981c8-023e-413e-85ae-162fc1c77bd5",
  "created_at": "2026-08-29 07:42:09.682838",
  "remediation_notes": null
}
```
**Analysis:** testidor_user successfully read a scan owned by a different user (owner_id: ba4981c8...). No authorization check performed. Endpoint returned full scan details including severity level and other sensitive fields. User can enumerate all scan IDs (even with UUIDs) and access unauthorized records. ✅ **EXPLOITATION CONFIRMED**

---

### 3. Logger Credential Disclosure - Login Attempt

| Property | Value |
|----------|-------|
| **Tool & Scan Type** | Semgrep (SAST) |
| **Location** | `app/main.py:192` |
| **Code** | `logger.info(f"Login attempt — username: {username} password: {password}")` |
| **Severity** | **HIGH** |
| **CWE** | CWE-532: Insertion of Sensitive Information into Log File |
| **Code Origin** | **New feature** (added in Task 1) |

**Justification:**
- Plaintext passwords logged to application logs
- Any user with log access (local developers, ops teams, log aggregation systems) can read credentials
- Passwords may be stored in log files, forwarded to Splunk/ELK/CloudWatch, or indexed by search engines in development environments

**Business Impact:**
- **Credential Exposure:** Users' passwords visible in plain text in log files (often `/var/log/app.log` or centralized logging)
- **Privilege Escalation:** Logs may be accessible to developers who shouldn't have production database passwords
- **Compliance:** GDPR Article 32, PCI-DSS 3.4 require protecting authentication data. This violates logging best practices.
- **Audit Trail Contamination:** Security logs become useless if they contain the very secrets they should protect

**Remediation:** Log only `"Login attempt for user: {username_hash}"` without password.

---

### 5. Logger Credential Disclosure - Failed Login

| Property | Value |
|----------|-------|
| **Tool & Scan Type** | Semgrep (SAST) |
| **Location** | `app/main.py:195-199` |
| **Code** | `logger.info(f"Failed login — username: '{username}' password: '{password}'")` |
| **Severity** | **HIGH** |
| **CWE** | CWE-532: Insertion of Sensitive Information into Log File |
| **Code Origin** | **New feature** (added in Task 1) |

**Justification:**
- Same as finding #4 — plaintext password in logs on failed login
- Actually more dangerous: failed logins are often logged at WARNING level and appear in security monitoring tools

**Business Impact:**
- Same as finding #4, plus potential use in brute-force attack analysis (attacker logs contain passwords being attempted)

**Remediation:** Log only `"Failed login for user: {username_hash}"` without password.

---

### 6. Hardcoded Database Password

| Property | Value |
|----------|-------|
| **Tool & Scan Type** | Manual code review |
| **Location** | `app/config.py:41` |
| **Code** | `DB_PASSWORD = "Tr@cker2024!"` |
| **Severity** | **CRITICAL** |
| **CWE** | CWE-798: Use of Hard-Coded Credentials |
| **Code Origin** | **New feature** (added in Task 1, but unused) |

**Justification:**
- Database password hardcoded as string literal in source code
- Exposed in git history and visible to anyone with repository access
- Although currently unused (not referenced), credentials in source control are critical risk
- Password appears strong, but hardcoding defeats all security benefits

**Business Impact:**
- **Compliance Violation:** PCI-DSS 3.2.1, SOC 2, HIPAA prohibit hardcoded credentials
- **Supply Chain Risk:** Anyone cloning repo gets database credentials
- **Incident Response:** If repo compromised, must rotate credentials across infrastructure
- **Git History:** Credentials visible forever (only removed with full rebase)

**Remediation:** Move to GitHub Secrets, load via environment variables at runtime

---

### 7. Hardcoded Admin API Key

| Property | Value |
|----------|-------|
| **Tool & Scan Type** | Manual code review |
| **Location** | `app/config.py:44` |
| **Code** | `ADMIN_API_KEY = "sk-vt-prod-8f3a2b1c9d4e5f6a7b8c9d0e1f2a3b4c"` |
| **Severity** | **HIGH** |
| **CWE** | CWE-798: Use of Hard-Coded Credentials |
| **Code Origin** | **New feature** (added in Task 1, but unused) |

**Justification:**
- Admin API key hardcoded in source code
- Follows production secret format ("sk-vt-prod-...") suggesting real key
- Currently unused, but if referenced, grants admin access to anyone with repo
- Harder to detect than passwords (appears as random hex string)

**Business Impact:**
- **Admin Access:** If used, anyone can assume admin privileges
- **Data Exfiltration:** Admin key allows access to all user data, scans, findings
- **Compliance:** Violates security standards requiring credential management
- **Key Rotation Cost:** Requires audit of all actions taken with this key

**Remediation:** Move to GitHub Secrets, load via environment variables

---

### 8. Hardcoded Database Username

| Property | Value |
|----------|-------|
| **Tool & Scan Type** | Manual code review |
| **Location** | `app/config.py:40` |
| **Code** | `DB_USER = "vulntracker_app"` |
| **Severity** | **HIGH** |
| **CWE** | CWE-798: Use of Hard-Coded Credentials |
| **Code Origin** | **New feature** (added in Task 1, but unused) |

**Justification:**
- Database username hardcoded (less sensitive than password alone, but still a credential)
- Stored alongside password in same file
- Violates least-privilege and secrets management principles

**Business Impact:**
- **Credential Pair Exposure:** Username + password together makes attacks trivial
- **Information Leakage:** Reveals database account naming convention

**Remediation:** Move to GitHub Secrets along with password

---

## Medium Findings

### 6. High-Severity Dependency Vulnerabilities (SCA)

| Property | Value |
|----------|-------|
| **Tool & Scan Type** | Grype (SCA scanning CycloneDX SBOM) |
| **Affected Packages** | Multiple (see reachability analysis below) |
| **Severity** | Varies by package and reachability |
| **Code Origin** | **Dependencies** (not custom code) |

**Reachability Analysis — Which Vulnerabilities Actually Matter:**

#### REACHABLE: cryptography (HIGH severity)

| CVE | Package | Vulnerability | Reachability |
|-----|---------|---|---|
| GHSA-x4qr-2fvf-3mr5 | cryptography 38.0.1 | Vulnerable OpenSSL in prebuilt wheels | **REACHABLE** |
| GHSA-3ww4-gg4f-jr7f | cryptography 38.0.1 | Bleichenbacher timing oracle in RSA padding | **REACHABLE** |

**Why reachable:** 
- VulnTracker uses `python-jose` (line: `from jose import jwt`) with RS256 algorithm (line: `jwt.encode(..., algorithm=ALGORITHM)`)
- python-jose relies on cryptography backend for RS256 asymmetric signing
- Callable path: `create_access_token()` → `jwt.encode()` → `jose.backends.cryptography_backend` → vulnerable OpenSSL

**Business Impact:**
- RS256 JWT tokens signed with this vulnerable cryptography version
- Timing oracle attack could potentially leak bits of the PRIVATE_KEY over many requests
- An attacker measuring response times on JWT validation could theoretically extract key material

**Severity:** **HIGH** — Affects authentication system, but requires sophisticated timing attacks

---

#### NOT REACHABLE: python-multipart (HIGH severity)

| CVE | Package | Vulnerability | Reachability |
|-----|---------|---|---|
| GHSA-wp53-j4wj-2cfg | python-multipart 0.0.6 | Arbitrary file write in file uploads | **NOT REACHABLE** |
| GHSA-2jv5-9r88-3w3p | python-multipart 0.0.6 | ReDoS in multipart boundary parsing | **NOT REACHABLE** |

**Why NOT reachable:**
- python-multipart is a transitive dependency (installed by FastAPI)
- VulnTracker has **no file upload endpoints** — only `/scans` (POST creates new scan) with JSON body, no `UploadFile` parameter
- grep confirms: `grep -rn "UploadFile\|multipart\|upload" app/` returns nothing
- The vulnerable code paths in python-multipart (file parsing, boundary parsing) are never invoked

**Severity:** **DOWNGRADED to LOW** — Present but unreachable in this application

**Remediation:** Can be deferred. However, good practice: remove unused dependency or upgrade FastAPI to version that depends on patched python-multipart.

---

#### REACHABLE: starlette (MEDIUM severity)

| CVE | Package | Vulnerability | Reachability |
|-----|---------|---|---|
| GHSA-86qp-5c8j-p5mr | starlette (via FastAPI) | Host header not validated in middleware | **REACHABLE** |

**Why reachable:**
- FastAPI depends on Starlette for HTTP middleware and request handling
- All HTTP requests pass through Starlette's middleware stack (line: `@app.middleware("http")`)
- If Host header validation is missing, request smuggling or cache poisoning is possible

**Business Impact:**
- An attacker can craft requests with malicious Host headers
- Could lead to cache poisoning (if caching layer exists), CSRF bypasses, or request smuggling
- Low risk in this case since VulnTracker is JSON API, not a traditional web app with cookies/session

**Severity:** **MEDIUM** — Reachable but low risk for this API-only application

---

**Summary of Reachability-Based Prioritization:**

| Package | Vulnerability | Reachable? | Severity | Priority |
|---------|---|---|---|---|
| cryptography | OpenSSL + timing oracle | ✅ YES | HIGH | **Update ASAP** |
| starlette | Host header validation | ✅ YES | MEDIUM | Update within sprint |
| python-multipart | File write + ReDoS | ❌ NO | **LOW** (downgraded) | Defer or remove dependency |

**Remediation Strategy:**
1. **CRITICAL:** `pip install --upgrade cryptography` (to fix RS256 JWT signing)
2. **MEDIUM:** `pip install --upgrade fastapi starlette` (to fix host header validation)
3. **OPTIONAL:** Remove python-multipart dependency (unused) or upgrade it anyway for supply chain hygiene

---

## Low Findings

### 5. Potential PKCS#12 Null Pointer Dereference

| Property | Value |
|----------|-------|
| **Tool & Scan Type** | Grype (SCA) |
| **Package** | cryptography (transitive via python-multipart or jwt) |
| **Severity** | **LOW** |
| **Impact** | Denial of Service (application crash) if malformed PKCS#12 cert is processed |
| **Code Origin** | **Dependencies** |

**Business Impact:** Low — requires attacker to provide malformed certificate, which VulnTracker doesn't currently parse. Monitor for updates.

---

## Summary Table (Sorted by Priority)

| Finding | Severity | Type | Status | PoC |
|---------|----------|------|--------|-----|
| SQL Injection in `/scans/search` | CRITICAL | SAST (Semgrep) | ⚠️ **Needs immediate fix** | ✅ Burp tested |
| Hardcoded Database Password | CRITICAL | Manual review | ⚠️ **Needs immediate fix** | Code inspection |
| IDOR in GET `/scans/{scan_id}` | HIGH | Manual review | ⚠️ **Needs immediate fix** | ✅ Burp tested |
| Hardcoded Admin API Key | HIGH | Manual review | ⚠️ **Needs immediate fix** | Code inspection |
| Hardcoded Database Username | HIGH | Manual review | ⚠️ **Needs immediate fix** | Code inspection |
| Logger credential leak (login attempt) | HIGH | SAST (Semgrep) | ⚠️ **Needs immediate fix** | Code inspection |
| Logger credential leak (failed login) | HIGH | SAST (Semgrep) | ⚠️ **Needs immediate fix** | Code inspection |
| Vulnerable cryptography (timing oracle) | HIGH | SCA (Grype) | ⚠️ **Needs urgent update** | Reachable via RS256 JWT |
| Vulnerable starlette (host header) | MEDIUM | SCA (Grype) | ⚠️ **Needs update** | Reachable via HTTP middleware |
| Vulnerable python-multipart (file write) | LOW | SCA (Grype) | Update in patch window | Not reachable (no uploads) |
| Vulnerable python-multipart (ReDoS) | LOW | SCA (Grype) | Update in patch window | Not reachable (no uploads) |
| PKCS#12 null pointer dereference | LOW | SCA (Grype) | Update in patch window | Not reachable |

---

## Remediation Strategy

**Phase 1 (This Task - Task 3):** Fix code-level vulnerabilities (CRITICAL/HIGH)
1. **Fix SQL Injection:** Use parameterized queries (SQLAlchemy ORM) instead of f-strings + `text()`
2. **Fix IDOR:** Add `owner_id` check to GET `/scans/{scan_id}` endpoint
3. **Remove hardcoded credentials:** Delete DB_USER, DB_PASSWORD, ADMIN_API_KEY from config.py
4. **Move secrets to GitHub Secrets:** Store credentials as repository secrets and load via environment variables
5. **Fix logger credential leaks:** Remove password logging from login endpoints

**Phase 2:** Update dependencies (MEDIUM/HIGH)
- `pip install --upgrade cryptography starlette` (python-multipart not reachable, can defer)
- Test application after updates

**Phase 3:** Add security tests and validation
- Test case for SQL injection payload prevention
- Test case for authorization checks (IDOR prevention)
- Test case for logging (ensure passwords not logged)
- Verify credentials loaded from GitHub Secrets in CI/CD

**GitHub Secrets Strategy:**
```
Store in GitHub Secrets:
- DB_PASSWORD
- DB_USER  
- ADMIN_API_KEY
- NOTIFY_SERVICE_URL (optional)
- DATABASE_URL (if needed for different environments)

Load in CI/CD workflow (.github/workflows/ci.yml):
- echo "DB_PASSWORD=${{ secrets.DB_PASSWORD }}" >> $GITHUB_ENV
- echo "DB_USER=${{ secrets.DB_USER }}" >> $GITHUB_ENV
- echo "ADMIN_API_KEY=${{ secrets.ADMIN_API_KEY }}" >> $GITHUB_ENV

Load in app/config.py:
- DB_USER = os.getenv("DB_USER")
- DB_PASSWORD = os.getenv("DB_PASSWORD")
- ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")
```
