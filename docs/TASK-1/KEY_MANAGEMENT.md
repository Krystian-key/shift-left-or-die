# JWT Key Management

## Overview

This application uses **RS256 (asymmetric) JWT** for authentication. Private keys must be carefully managed to prevent unauthorized token generation.

---

## Development Setup

### Local Key Generation

Keys are generated locally (one-time):
```bash
openssl genrsa -out app/private_key.pem 2048
openssl rsa -in app/private_key.pem -pubout -out app/public_key.pem
```

### Development Key Storage

Keys are stored **base64-encoded** in `.env.local` (never committed to repo):

```bash
# .env.local (gitignored — DO NOT COMMIT)
JWT_PRIVATE_KEY_B64=MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEA...
JWT_PUBLIC_KEY_B64=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
```

**Why base64?**
- PEM format has newlines — hard to store in env vars
- Base64 encoding makes it a single-line value
- `config.py` automatically decodes when loading

### Testing

`tests/conftest.py` auto-loads `.env.local` before running tests:
```python
# pytest auto-loads .env.local
os.environ[key] = value  # JWT_PRIVATE_KEY_B64, etc.
```

Run tests:
```bash
source .venv/bin/activate
python -m pytest tests/test_api.py
```

---

## Production Setup

### Key Storage Strategy

**Never commit keys to repository.** Load from secret manager:

```python
# config.py supports multiple sources (generic approach):
PRIVATE_KEY = os.getenv("JWT_PRIVATE_KEY")  # Plain PEM or base64
PUBLIC_KEY = os.getenv("JWT_PUBLIC_KEY")
```

### Recommended: Google Secret Manager

```bash
# Store keys in Google Secret Manager
gcloud secrets create jwt-private-key --data-file=private_key.pem
gcloud secrets create jwt-public-key --data-file=public_key.pem

# At runtime, inject via env vars:
export JWT_PRIVATE_KEY=$(gcloud secrets versions access latest --secret=jwt-private-key)
export JWT_PUBLIC_KEY=$(gcloud secrets versions access latest --secret=jwt-public-key)

# Then start app
uvicorn app.main:app
```

### Alternative: AWS Secrets Manager

```bash
# Store as JSON secret
aws secretsmanager create-secret \
  --name prod/jwt-keys \
  --secret-string '{"private":"-----BEGIN...","public":"-----BEGIN..."}'

# Retrieve at runtime (e.g., in deployment startup script)
SECRET=$(aws secretsmanager get-secret-value --secret-id prod/jwt-keys)
export JWT_PRIVATE_KEY=$(echo $SECRET | jq -r '.private')
export JWT_PUBLIC_KEY=$(echo $SECRET | jq -r '.public')
```

### Alternative: HashiCorp Vault

```bash
# Store keys in Vault
vault kv put secret/jwt \
  private_key=@private_key.pem \
  public_key=@public_key.pem

# Retrieve at runtime
vault kv get -field=private_key secret/jwt > /tmp/private_key.pem
export JWT_PRIVATE_KEY=$(cat /tmp/private_key.pem)
export JWT_PUBLIC_KEY=$(vault kv get -field=public_key secret/jwt)
```

---

## Key Rotation

For production key rotation:

1. Generate new key pair
2. Store new keys in secret manager
3. Update environment variables in deployment
4. Existing tokens remain valid until expiry (30 minutes by default)
5. New tokens use new key

---

## Security Checklist

- ✅ Private keys never committed to git
- ✅ `.env.local` is gitignored
- ✅ `private_key.pem` / `public_key.pem` are gitignored
- ✅ Production loads from secret manager
- ✅ No hardcoded keys in code
- ✅ Environment variable names are generic (not tied to one provider)

---

## Code References

**Loading logic** (`app/config.py`):
```python
PRIVATE_KEY = os.getenv("JWT_PRIVATE_KEY")
if not PRIVATE_KEY:
    private_key_b64 = os.getenv("JWT_PRIVATE_KEY_B64")
    if private_key_b64:
        PRIVATE_KEY = base64.b64decode(private_key_b64).decode()
```

**Testing setup** (`tests/conftest.py`):
```python
def pytest_configure(config):
    env_file = Path(__file__).parent.parent / ".env.local"
    if env_file.exists():
        # Load .env.local variables
        os.environ[key] = value
```

**JWT creation** (`app/auth.py`):
```python
token = jwt.encode(to_encode, PRIVATE_KEY, algorithm="RS256")
```

**JWT verification** (`app/auth.py`):
```python
payload = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])  # No "none"!
```

---

## Troubleshooting

**Error: "JWT_PRIVATE_KEY and JWT_PUBLIC_KEY must be set"**
- For dev: Ensure `.env.local` is created and has base64 keys
- For prod: Ensure secret manager is configured and env vars are injected

**Error: "Invalid signature"**
- Verify public key matches the private key that signed the token
- Check for newline/encoding issues in base64 decoding

**Error: "Unsupported algorithm"**
- Ensure only RS256 is in `algorithms` list (no "none"!)
- See `app/auth.py:52` — `algorithms=[ALGORITHM]` where `ALGORITHM="RS256"`
