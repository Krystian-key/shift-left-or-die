# TASK 1 — SHARED REPORT LINK — IMPLEMENTATION SUMMARY

## Files Changed

**Added:**
- `app/share.py` — Token/password helpers (generation, hashing, verification, logging sanitization)
- `TASK1_SUMMARY.md` — This summary

**Modified:**
- `app/models.py` — Added `ScanShare` model (token_hash, scan_id, password_hash, expires_at)
- `app/main.py` — Added endpoints (`POST /scans/{scan_id}/share`, `GET /share/{token}`), exception handler sanitization, schemas (ShareCreate, ShareOut, SharedScanOut)
- `tests/test_api.py` — Added 17 test cases (ownership, token storage, password hashing, expiry, DTO filtering, security headers)

---

## Security Design Decisions

| Decision | Implementation |
|----------|----------------|
| **Token Generation** | CSPRNG via `secrets.token_urlsafe(32)` |
| **Token Storage** | SHA-256 one-way digest; raw share tokens never persisted in database |
| **Password Hashing** | Bcrypt with 72-byte UTF-8 validation (prevents truncation collisions) |
| **Expiry** | Exact 24-hour boundary (`now >= expires_at`) |
| **Authorization** | Object-level: query both `id` AND `owner_id` before sharing (anti-IDOR) |
| **Public Response** | Explicit `SharedScanOut` DTO; `owner_id` excluded |
| **Error Handling** | Generic "Share link not found or expired" (no state disclosure) |
| **Log Sanitization** | `/share/[REDACTED]` for sensitive paths |
| **Cache Control** | `Cache-Control: no-store` header on share responses |
| **Referrer Policy** | `Referrer-Policy: no-referrer` header on share responses |

---

## Test Results

```
27 passed in 11.51s
✅ 10 original API tests (untouched, all pass)
✅ 17 new share tests (all pass)
```

Key coverage:
- Ownership verification (IDOR prevention)
- Token storage (raw ≠ stored, hash only)
- Password storage (bcrypt hash only, plaintext never stored)
- Bcrypt 72-byte limit enforcement
- 24-hour expiry (exact boundary)
- DTO filtering (no owner_id leakage)
- Security headers (Cache-Control, Referrer-Policy)
- Generic error handling

---

## Residual Architectural Limitation

**Credentials in URL** — The required API places the share capability in the URL path (`/share/{token}`) and, for password-protected shares, the password in the query string (`?password=...`). Application-level mitigations (log sanitization, cache headers, referrer policy) reduce but cannot eliminate exposure in browser history or upstream infrastructure (proxy, WAF, load balancer, APM) logs.

---

## Out-of-Scope Enhancement

**Early revocation** — Share links remain valid until their 24-hour expiry. Early revocation was intentionally not implemented because it is not required by Task 1 specification.

---

## Verification Checklist

- ✅ token_hash has `unique=True, index=True`
- ✅ owner_id excluded from SharedScanOut DTO
- ✅ POST queries `id AND owner_id` (IDOR prevention)
- ✅ GET checks `now >= expires_at` (exact boundary)
- ✅ Exception handler sanitizes `/share/[REDACTED]`
- ✅ Raw token never stored in database
- ✅ Bcrypt limit checks UTF-8 bytes (`len(password.encode())`)
- ✅ All tests pass (27/27)

---

**Task 1 complete. Ready for submission.**
