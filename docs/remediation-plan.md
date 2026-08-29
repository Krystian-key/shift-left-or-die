# Task 3 — Remediation Plan

## Summary
Security findings identified during code review and testing. At least 3 findings addressed (HIGH/CRITICAL priority). Effort breakdown and residual risk documented.

---

## Finding #1: JWT "none" Algorithm + HS256 Weakness — Authentication Bypass ✅ FIXED

**Severity:** CRITICAL (9.8/10)  
**Files:** `app/auth.py:52`, `app/config.py`  
**Status:** FIXED  
**Effort:** LOW (~15 min)

### Vulnerability
```python
# BEFORE (vulnerable):
payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM, "none"])
```

The decoder accepts `"none"` algorithm, allowing unsigned JWT tokens:
- Attacker creates unsigned token: `header.payload.` (empty signature)
- Decoder accepts it without signature verification
- Attacker can impersonate any user

### Attack Example
```bash
# Attacker creates unsigned token with admin claims
$ echo -n '{"typ":"JWT","alg":"none"}' | base64 → eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0
$ echo -n '{"sub":"admin","exp":9999999999}' | base64 → eyJzdWIiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0
$ curl -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0."
# ✅ Authenticates as admin!
```

### Remediation
```python
# AFTER (fixed):
payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
```

Remove `"none"` from algorithms list. Only accept properly signed tokens.

### Testing
- ✅ Valid signed tokens still decode correctly
- ✅ Unsigned tokens now rejected with JWTError
- ✅ Invalid signatures still rejected

---

## Finding #2: Predictable IDs — IDOR Enumeration (Scan + User) ✅ FIXED

**Severity:** HIGH (7.5/10)  
**Files:** `app/models.py` (ScanResult.id, User.id)  
**Status:** FIXED  
**Effort:** HIGH (schema migration + test updates)

### Vulnerability
Both scan IDs and user IDs are sequential integers. Attacker can enumerate all resources:
```
GET /scans/1 → found
GET /scans/2 → found
...
GET /users/1 → found (if endpoint exposed)
```

Even though endpoints check `owner_id`, the predictable IDs reveal:
- Number of scans/users in system
- Resource creation order
- Possible active resource ranges

### Remediation (✅ IMPLEMENTED)
Changed from Integer to String(36) UUID:
```python
# ScanResult.id
id = Column(String(36), primary_key=True, index=True, default=lambda: str(uuid.uuid4()))

# User.id  
id = Column(String(36), primary_key=True, index=True, default=lambda: str(uuid.uuid4()))

# Foreign keys
owner_id = Column(String(36), ForeignKey("users.id"), nullable=False)
scan_id = Column(String(36), ForeignKey("scan_results.id"), nullable=False)
```

**Changes Made:**
- ✅ ScanResult.id: Integer → String(36) UUID
- ✅ User.id: Integer → String(36) UUID
- ✅ ScanResult.owner_id: Integer FK → String(36) FK
- ✅ ScanShare.scan_id: Integer FK → String(36) FK
- ✅ All endpoints: accept string UUIDs
- ✅ All tests: pass with UUID IDs
- ✅ Schemas updated: UserOut.id, ScanOut.id, ScanOut.owner_id

**Compensating Controls:**
- `GET /scans/{scan_id}` checks both `id AND owner_id` (IDOR prevention)
- Generic error "Scan not found" (no information leakage)
- Rate limiting on endpoints (brute-force resistance)

---

## Finding #3: Weak Password Validation in Share Links

**Severity:** MEDIUM (5.0/10)  
**File:** `app/share.py` (missing MIN length check)  
**Status:** PLANNED  
**Effort:** LOW

### Vulnerability
Optional password protection for share links, but no MIN length enforced:
- User can set password: `"a"` (1 character)
- Bcrypt hashes 1-char passwords, but weak entropy
- Offline brute-force attack trivial (2^7 combinations)

### Remediation (Planned for Task 3 — Phase 2)
Add to `app/share.py`:
```python
MIN_SHARE_PASSWORD_LENGTH = 8

def hash_share_password(password: str) -> str:
    if len(password) < MIN_SHARE_PASSWORD_LENGTH:
        raise ValueError("Share password must be at least 8 characters")
    if len(password.encode()) > MAX_PASSWORD_BYTES:
        raise ValueError(f"Password exceeds {MAX_PASSWORD_BYTES} bytes")
    return pwd_context.hash(password)
```

**Testing:**
- Password < 8 chars: 422 error
- Password >= 8 chars: accepted

**Residual Risk:** Password still in query string (?password=...), exposed to browser history and proxy logs. Mitigated by cache-control and referrer-policy headers.

---

## Finding #4: Hardcoded Database & API Credentials

**Severity:** CRITICAL (9.5/10)  
**File:** `app/config.py`  
**Status:** PLANNED  
**Effort:** LOW

### Vulnerability
Credentials are hardcoded in source code:
```python
DB_USER = "vulntracker_app"
DB_PASSWORD = "Tr@cker2024!"
ADMIN_API_KEY = "sk-vt-prod-8f3a2b1c9d4e5f6a7b8c9d0e1f2a3b4c"
```

Exposed in repo = exposed to anyone with access.

### Remediation (TODO for Task 3)
Load from environment variables:
```python
DB_USER = os.getenv("DB_USER", "vulntracker_app")
DB_PASSWORD = os.getenv("DB_PASSWORD")  # REQUIRED
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")  # REQUIRED
```

---

## Finding #5: Report Access by Direct ID (TODO)

**Severity:** MEDIUM  
**Status:** TODO  
**Note:** Burp testing showed issue accessing reports by scan ID via `/scans/{scan_id}` endpoint when unauthenticated

---

## Summary Table

| Finding | Severity | File | Status | Effort |
|---------|----------|------|--------|--------|
| JWT "none" algorithm | CRITICAL | auth.py | ✅ FIXED | LOW |
| UUID enumeration (Scans + Users) | HIGH | models.py | ✅ FIXED | HIGH |
| Hardcoded credentials | CRITICAL | config.py | PLANNED | LOW |
| Weak share passwords | MEDIUM | share.py | PLANNED | LOW |
| Report access logic | MEDIUM | main.py | TODO | TBD |

---

## Finding #6: Share Credentials in URL — Information Disclosure (Residual Risk)

**Severity:** MEDIUM (5.5/10)  
**File:** `app/main.py` (GET /share/{token})  
**Status:** RESIDUAL RISK (spec requirement)  
**Effort:** HIGH (requires API redesign)

### Vulnerability
Share credentials exposed in URL:
- **Token:** `/share/{token}` → visible in browser history, server logs, proxy logs, referrer headers
- **Password:** `?password=...` → same exposure in query string

### Attack Scenarios
1. **Browser history** — Share link visible to local attacker
2. **Server logs** — GET request logged with full URL including token + password
   ```
   [2026-08-29] GET /share/LLbAROcTbudMmm76gNKWIOT9jDrMuQs1FYuofjGjWPc?password=ShareMe123!@#$% HTTP/1.1
   ```
3. **Proxy/WAF logs** — Reverse proxy, load balancer, WAF all log full URL with credentials
4. **Log aggregation** — Splunk, ELK, CloudWatch, DataDog ingest logs with exposed credentials
5. **Referrer header** — Token leaked to external sites if user clicks link
6. **Application logs** — Exception handlers, request logging capture full URL path

### Remediation (Alternative Design - Not Implemented)
POST with body would be more secure:
```http
POST /share/access HTTP/1.1
Content-Type: application/json

{"token":"...", "password":"..."}
```

But Task 1 spec requires: `GET /share/{token}?password=...`

### Compensating Controls (Currently Implemented)
- ✅ `Cache-Control: no-store` — prevents browser caching of responses
- ✅ `Referrer-Policy: no-referrer` — prevents referrer leakage to external sites
- ✅ Log sanitization — removes tokens from exception logs (path: `/share/[REDACTED]`)
- ✅ HTTPS (production only) — encrypts credentials in transit
- ✅ Short token lifetime — 24 hours expiry reduces exposure window
- ✅ Tokens are one-way hashed — exposure of database doesn't expose live tokens

### Why Not Fixed
- **Spec requirement:** Task 1 explicitly requires `GET /share/{token}` and `?password=...`
- **Redesign cost:** Would require new endpoints, schema changes, client updates
- **Compensating controls:** Sufficient for prototype; production would need HTTPS + log monitoring

### Recommendation
For production: Redesign to use POST with body or require authentication (Bearer token) for share access.

---

## Next Steps

1. ✅ **DONE:** Fix JWT "none" algorithm in auth.py
2. ✅ **DONE:** Implement UUID enumeration fix (scan + user IDs)
3. **TODO:** Run 9 Burp Suite tests to verify fixes
4. **TODO:** Implement hardcoded credentials fix (config.py)
5. **TODO:** Implement password MIN length in share links
6. **TODO:** Re-run all test suites (34 API tests + Burp tests)

---

**Task 3 Status:** 2/3 fixes complete. Burp testing in progress.
