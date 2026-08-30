# Task 4: Containerization & Deployment Testing

Complete testing documentation for Task 4 (Dockerfile, Docker Compose, Kubernetes/Helm).

## 📋 Test Documentation

### Phase 1: Docker Image Build & Security
**File:** `01-DOCKER-BUILD-TEST.md`

Tests:
1. ✅ Docker image builds successfully
2. ✅ Image properties (size, user UID)
3. ✅ Container execution with security flags
4. ✅ Read-only filesystem enforcement
5. ✅ Security flags applied (no-new-privileges, cap-drop ALL)

**Duration:** ~10 minutes

---

### Phase 2: Kubernetes Deployment (minikube)
**File:** `02-KUBERNETES-MINIKUBE-TEST.md`

Tests:
1. ✅ minikube cluster starts
2. ✅ Docker image loads into minikube
3. ✅ Kubernetes secrets created
4. ✅ Helm chart deployment succeeds
5. ✅ Pods reach Running state
6. ✅ API endpoints respond
7. ✅ SecurityContext applied (UID 65532, read-only FS)
8. ✅ ServiceAccount token NOT mounted
9. ✅ NetworkPolicy enforced
10. ✅ Resource limits applied
11. ✅ HPA scaling works

**Duration:** ~15 minutes

---

## 🚀 Quick Start

### Prerequisites
```bash
# Check installations
docker --version        # 24.0+
minikube version       # v1.30+
kubectl version        # v1.26+
helm version          # v3.12+

# Get JWT keys from .env.local (needed for tests)
grep JWT_PRIVATE_KEY_B64 .env.local
grep JWT_PUBLIC_KEY_B64 .env.local
```

### Run All Tests (Sequential)

```bash
# Step 1: Docker Tests (10 min)
echo "=== Starting Docker Build Tests ==="
cd /Users/krystiankluczkiewicz/Desktop/standard-task/shift-left-or-die
docker build -t vulntracker-api:1.0.0 .

# Run tests from 01-DOCKER-BUILD-TEST.md (sections 1.1-1.5)

# Step 2: Kubernetes Tests (15 min)
echo "=== Starting Kubernetes Tests ==="

# Run minikube setup and Helm deployment (from 02-KUBERNETES-MINIKUBE-TEST.md)
# Sections 2.1-2.12

# Step 3: Summary
echo "=== All Tests Complete ==="
```

---

## ✅ Testing Checklist

### Phase 1: Docker
- [ ] Docker image builds (no errors)
- [ ] Image size < 150MB
- [ ] User UID is 65532:65532
- [ ] Container starts with read-only FS
- [ ] Health endpoint responds (200 OK)
- [ ] Cannot write to /app (read-only)
- [ ] Can write to /tmp (tmpfs)
- [ ] Security flags applied (ReadonlyRootfs, no-new-privileges, CapDrop ALL)

### Phase 2: Kubernetes
- [ ] minikube cluster starts
- [ ] Kubernetes 1.28+ running
- [ ] Image loads into minikube Docker
- [ ] Secrets created (jwt-keys, db-credentials, admin-api)
- [ ] Helm chart deploys
- [ ] Both replicas Running
- [ ] Service created (ClusterIP)
- [ ] HPA created (minReplicas: 2, maxReplicas: 5)
- [ ] Pod logs show "Application startup complete"
- [ ] Health endpoint responds (curl)
- [ ] SecurityContext: runAsUser 65532, nonroot, read-only FS
- [ ] ServiceAccount token NOT mounted
- [ ] Cannot write to /app (read-only)
- [ ] Can write to /tmp (tmpfs)
- [ ] NetworkPolicy exists and shows correct rules
- [ ] Resource limits applied (CPU 500m, Memory 512Mi)
- [ ] HPA scales under load (replica count increases)

---

## 🔍 Key Files in This Test Suite

```
docs/TASK-4/
├── README.md                           # This file
├── 01-DOCKER-BUILD-TEST.md             # Docker image tests
├── 02-KUBERNETES-MINIKUBE-TEST.md      # Kubernetes/Helm tests
└── TEST-RESULTS.md                     # Results documentation
```

---

## 📊 Expected Results

### Docker Build
- **Image size:** ~100-120MB (distroless base)
- **Build time:** ~3-5 minutes (first build)
- **User UID:** 65532:65532
- **Base image:** gcr.io/distroless/python3.11

### Kubernetes Deployment
- **Startup time:** ~20-30 seconds
- **Ready pods:** 2/2
- **Pod age:** ~30 seconds (from deployment creation)
- **Health check:** 200 OK
- **Resource requests:** CPU 100m, Memory 128Mi
- **Resource limits:** CPU 500m, Memory 512Mi

---

## 🛠️ Troubleshooting

### Docker Build Fails
```bash
# Check Docker daemon
docker info

# Check disk space
df -h

# Check Dockerfile syntax
docker build --no-cache -t vulntracker-api:1.0.0 .
```

### Minikube Cluster Issues
```bash
# Reset minikube
minikube delete
minikube start --cpus=4 --memory=4096

# Check cluster status
kubectl cluster-info
kubectl get nodes
```

### Pods Won't Start
```bash
# Check events
kubectl describe pod -n vulntracker <pod-name>

# Check logs
kubectl logs -n vulntracker <pod-name>

# Check resource availability
minikube describe nodes
```

### API Endpoint Unreachable
```bash
# Check service
kubectl get svc -n vulntracker

# Check port-forward
kubectl port-forward -n vulntracker svc/vulntracker-api 8000:8000

# Test from pod
kubectl exec -n vulntracker deployment/vulntracker-api -- curl http://localhost:8000/health
```

---

## 📝 Test Report Template

After running tests, document results:

```markdown
## Test Execution Report

**Date:** YYYY-MM-DD
**Tester:** [Name]
**Environment:** macOS / Docker / minikube

### Phase 1: Docker Build ✅/❌
- Image build: PASS/FAIL
- Image size: XXX MB
- User UID: 65532:65532 PASS/FAIL
- Read-only FS: PASS/FAIL
- Health endpoint: PASS/FAIL
- Security flags: PASS/FAIL

**Notes:** 

### Phase 2: Kubernetes ✅/❌
- Cluster start: PASS/FAIL
- Image load: PASS/FAIL
- Helm deploy: PASS/FAIL
- Pods running: PASS/FAIL
- API response: PASS/FAIL
- SecurityContext: PASS/FAIL
- NetworkPolicy: PASS/FAIL
- HPA scaling: PASS/FAIL

**Notes:**

### Overall Result
- Docker: ✅ PASS / ❌ FAIL
- Kubernetes: ✅ PASS / ❌ FAIL

**Blockers:** None / [List any blocking issues]
```

---

## 🎯 Success Criteria for Task 4 Completion

**All of the following must pass:**

1. ✅ Docker image builds without errors
2. ✅ Docker image size < 150MB
3. ✅ Docker image runs with read-only FS
4. ✅ Helm chart lints without errors
5. ✅ Kubernetes pods reach Running state
6. ✅ SecurityContext applied correctly (UID 65532, read-only FS)
7. ✅ ServiceAccount token NOT mounted
8. ✅ NetworkPolicy enforced
9. ✅ Resource limits applied
10. ✅ HPA can scale

**If ANY test fails:**
- Document the failure in TEST-RESULTS.md
- Fix the issue
- Re-run the test
- Do NOT commit until all tests pass

---

## 🚀 Next Steps After Testing

1. **All tests pass?**
   - Commit changes to `task-4` branch
   - Document test results in TEST-RESULTS.md
   - Create pull request to main

2. **Tests fail?**
   - Review the specific test that failed
   - Check the troubleshooting section
   - Fix the issue
   - Re-run tests
   - Loop until all pass

---

## ⏱️ Estimated Total Time

- **Docker tests:** 10 minutes
- **Kubernetes setup:** 5 minutes
- **Kubernetes tests:** 15 minutes
- **Documentation:** 5 minutes

**Total:** ~35 minutes for full test suite

---

## 📚 References

- Dockerfile: `/Dockerfile`
- Helm Chart: `/helm/vulntracker-api/`
- Docker Compose: `/docker-compose.prod.yml`
- Security Hardening: `/docs/SECURITY_HARDENING.md`
- Testing Guide: `/docs/TESTING_GUIDE.md`

---

## 💡 Tips

1. **Save JWT keys locally** for quick secret creation:
   ```bash
   JWT_PRIV=$(grep JWT_PRIVATE_KEY_B64 .env.local | cut -d= -f2)
   JWT_PUB=$(grep JWT_PUBLIC_KEY_B64 .env.local | cut -d= -f2)
   ```

2. **Reuse minikube cluster** across multiple test runs:
   ```bash
   # Don't delete, just stop
   minikube stop  # Instead of minikube delete
   minikube start # To restart
   ```

3. **Monitor logs in real-time:**
   ```bash
   kubectl logs -f -n vulntracker -l app=vulntracker-api
   ```

4. **Watch resource usage:**
   ```bash
   watch kubectl top pods -n vulntracker
   ```
