# Task 4: Docker Build Test

## Overview
Test Docker image build, security properties, and local execution.

## Prerequisites
```bash
docker --version  # Docker 24.0+
```

## Test Steps

### 1.1 Build Docker Image

**Command:**
```bash
cd /Users/krystiankluczkiewicz/Desktop/standard-task/shift-left-or-die
docker build -t vulntracker-api:1.0.0 .
```

**Expected Output:**
```
[+] Building 2m45s (13/13) FINISHED
 => [builder 6/6] RUN pip install --no-cache-dir --require-hashes --only-binary=:all:...
 => exporting to image
 => => naming to docker.io/library/vulntracker-api:1.0.0
```

**Success Criteria:**
- ✅ Build completes without errors
- ✅ All layers build successfully
- ✅ Final image created

---

### 1.2 Verify Image Properties

**Command:**
```bash
# Check image size
docker images vulntracker-api:1.0.0

# Check user/UID
docker inspect vulntracker-api:1.0.0 | jq '.ContainerConfig.User'
```

**Expected Output:**
```
REPOSITORY              TAG       IMAGE ID       SIZE
vulntracker-api         1.0.0     abc123def456   ~100MB

"65532:65532"
```

**Success Criteria:**
- ✅ Image size < 150MB
- ✅ User is `65532:65532` (Distroless nonroot)
- ✅ Image ID is consistent

---

### 1.3 Test Image Execution (Read-Only FS)

**Command:**
```bash
docker run --rm \
  --read-only \
  --security-opt no-new-privileges:true \
  --cap-drop ALL \
  --tmpfs /tmp \
  --tmpfs /var/tmp \
  -e JWT_PRIVATE_KEY_B64="$(grep JWT_PRIVATE_KEY_B64 /Users/krystiankluczkiewicz/Desktop/standard-task/shift-left-or-die/.env.local | cut -d= -f2)" \
  -e JWT_PUBLIC_KEY_B64="$(grep JWT_PUBLIC_KEY_B64 /Users/krystiankluczkiewicz/Desktop/standard-task/shift-left-or-die/.env.local | cut -d= -f2)" \
  -e DB_USER=testuser \
  -e DB_PASSWORD=testpass \
  -e ADMIN_API_KEY=testkey \
  -p 8000:8000 \
  vulntracker-api:1.0.0
```

**In another terminal, test:**
```bash
# Wait 5 seconds for startup
sleep 5

# Test health endpoint
curl http://localhost:8000/health

# Test API docs
curl http://localhost:8000/docs -I

# Test swagger JSON
curl http://localhost:8000/openapi.json -I
```

**Expected Output:**
```
{"status":"ok"}
HTTP/1.1 200 OK
HTTP/1.1 200 OK
```

**Success Criteria:**
- ✅ Container starts without errors
- ✅ Application startup completes
- ✅ Health endpoint responds
- ✅ API docs available
- ✅ No permission errors on read-only FS
- ✅ /tmp and /var/tmp writable (tmpfs)

---

### 1.4 Verify No Root FS Writes

**Command:**
```bash
docker run --rm \
  --read-only \
  --security-opt no-new-privileges:true \
  --cap-drop ALL \
  --tmpfs /tmp \
  -e JWT_PRIVATE_KEY_B64="$(grep JWT_PRIVATE_KEY_B64 .env.local | cut -d= -f2)" \
  -e JWT_PUBLIC_KEY_B64="$(grep JWT_PUBLIC_KEY_B64 .env.local | cut -d= -f2)" \
  -e DB_USER=testuser \
  -e DB_PASSWORD=testpass \
  -e ADMIN_API_KEY=testkey \
  vulntracker-api:1.0.0 \
  touch /app/test.txt
```

**Expected Output:**
```
touch: cannot touch '/app/test.txt': Read-only file system
```

**Success Criteria:**
- ✅ Write to read-only filesystem is BLOCKED
- ✅ Permission denied error

---

### 1.5 Check Security Flags Applied

**Command:**
```bash
docker run --rm \
  --read-only \
  --security-opt no-new-privileges:true \
  --cap-drop ALL \
  --tmpfs /tmp \
  -e JWT_PRIVATE_KEY_B64="$(grep JWT_PRIVATE_KEY_B64 .env.local | cut -d= -f2)" \
  -e JWT_PUBLIC_KEY_B64="$(grep JWT_PUBLIC_KEY_B64 .env.local | cut -d= -f2)" \
  -e DB_USER=testuser \
  -e DB_PASSWORD=testpass \
  -e ADMIN_API_KEY=testkey \
  -d \
  --name test-container \
  vulntracker-api:1.0.0

# Check security options
docker inspect test-container | jq '.HostConfig | {ReadonlyRootfs, SecurityOpt, CapDrop}'

# Cleanup
docker stop test-container
docker rm test-container
```

**Expected Output:**
```json
{
  "ReadonlyRootfs": true,
  "SecurityOpt": [
    "no-new-privileges=true"
  ],
  "CapDrop": [
    "ALL"
  ]
}
```

**Success Criteria:**
- ✅ ReadonlyRootfs: true
- ✅ no-new-privileges: true
- ✅ CapDrop: ALL

---

## Test Results

| Test | Status | Notes |
|------|--------|-------|
| Image Build | ⚠️ PENDING | Run: `docker build -t vulntracker-api:1.0.0 .` |
| Image Size | ⚠️ PENDING | Run: `docker images vulntracker-api` |
| User UID | ⚠️ PENDING | Expected: 65532:65532 |
| Health Endpoint | ⚠️ PENDING | Expected: 200 OK |
| Read-Only FS | ⚠️ PENDING | Expected: BLOCKED writes |
| Security Flags | ⚠️ PENDING | Expected: all flags applied |

---

## Notes

- All environment variables (JWT keys) loaded from `.env.local`
- Database connection will fail (SQLite for local testing only)
- Application should log: "Application startup complete"
- No actual database operations tested here (that's in Kubernetes tests)

---

## Next Steps

After Docker tests pass:
1. Proceed to Kubernetes tests (minikube)
2. Run Helm deployment
3. Validate SecurityContext and NetworkPolicy
