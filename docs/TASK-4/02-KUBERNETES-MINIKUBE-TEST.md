# Task 4: Kubernetes (minikube) Deployment Test

## Overview
Test complete Kubernetes deployment with Helm chart, security context, NetworkPolicy, and resource limits.

## Prerequisites

```bash
minikube version           # v1.30+
kubectl version --client   # v1.26+
helm version              # v3.12+
docker --version          # For building image
```

## Test Steps

### 2.1 Start minikube with Calico CNI

**Command:**
```bash
# IMPORTANT: Use --cni=calico for NetworkPolicy enforcement
# Without Calico (or another CNI), NetworkPolicy rules are NOT enforced
minikube start \
  --cpus=4 \
  --memory=4096 \
  --kubernetes-version=v1.28.0 \
  --container-runtime=docker \
  --cni=calico

# Verify cluster
kubectl cluster-info
kubectl get nodes

# Verify Calico is running
kubectl get daemonset -n calico-system
```

**Expected Output:**
```
😄  minikube v1.31.2 on Darwin 25.6.0
✨  Automatically selected the docker driver
📦  Starting control plane node minikube in cluster minikube
🐳  Pulling base image ...
🔌 Installing CNI (calico) ...
✅  minikube cluster started successfully

Kubernetes control plane is running at https://192.168.49.2:8443
...
NAME       STATUS   ROLES           AGE     VERSION
minikube   Ready    control-plane   1m46s   v1.28.0

# Calico system pods
NAMESPACE        NAME                                       READY   STATUS
calico-system    calico-kube-controllers-abc123def456-xyz   1/1     Running
calico-system    calico-node-abcde                          1/1     Running
```

**Success Criteria:**
- ✅ minikube cluster starts with Calico CNI
- ✅ Node shows "Ready" status
- ✅ kubectl can connect
- ✅ Calico daemonset pods are Running (required for NetworkPolicy enforcement)

---

### 2.2 Build and Load Docker Image

**Command:**
```bash
# Set Docker environment to minikube
eval $(minikube docker-env)

# Navigate to project
cd /Users/krystiankluczkiewicz/Desktop/standard-task/shift-left-or-die

# Build image (in minikube's Docker)
docker build -t vulntracker-api:1.0.0 .

# Verify image is in minikube
docker images | grep vulntracker-api
```

**Expected Output:**
```
REPOSITORY                TAG       IMAGE ID       SIZE
vulntracker-api           1.0.0     abc123def456   ~100MB
```

**Success Criteria:**
- ✅ Image builds successfully
- ✅ Image appears in minikube's Docker registry

---

### 2.3 Create Kubernetes Secrets

**Command:**
```bash
# Create namespace
kubectl create namespace vulntracker

# Get JWT keys from .env.local
JWT_PRIV=$(grep JWT_PRIVATE_KEY_B64 .env.local | cut -d= -f2)
JWT_PUB=$(grep JWT_PUBLIC_KEY_B64 .env.local | cut -d= -f2)

# Create secrets
kubectl create secret generic vulntracker-jwt-keys \
  --from-literal=private-key-b64="$JWT_PRIV" \
  --from-literal=public-key-b64="$JWT_PUB" \
  -n vulntracker

# DATABASE_URL: full connection string (not split username/password)
# For testing with SQLite: sqlite:///app/vulntracker.db
# For PostgreSQL: postgresql://user:password@postgres:5432/vulntracker
kubectl create secret generic vulntracker-db-credentials \
  --from-literal=database-url="sqlite:///app/vulntracker.db" \
  -n vulntracker

kubectl create secret generic vulntracker-admin-api \
  --from-literal=api-key=testkey \
  -n vulntracker

# Verify secrets
kubectl get secrets -n vulntracker
```

**Expected Output:**
```
NAME                         TYPE     DATA   AGE
vulntracker-jwt-keys         Opaque   2      5s
vulntracker-db-credentials   Opaque   1      4s
vulntracker-admin-api        Opaque   1      3s
```

**Success Criteria:**
- ✅ All 3 secrets created
- ✅ DATABASE_URL contains full connection string (not split credentials)
- ✅ Data count: jwt-keys (2), db-credentials (1), admin-api (1)

---

### 2.4 Deploy Helm Chart

**Command:**
```bash
helm install vulntracker-api ./helm/vulntracker-api/ \
  --namespace vulntracker \
  --set image.repository=vulntracker-api \
  --set image.tag=1.0.0 \
  --set image.pullPolicy=Never

# Wait for rollout
kubectl rollout status deployment/vulntracker-api -n vulntracker --timeout=2m

# Check deployment
kubectl get all -n vulntracker
```

**Expected Output:**
```
NAME: vulntracker-api
...
STATUS: deployed
REVISION: 1

NAME                                    READY   STATUS    RESTARTS   AGE
pod/vulntracker-api-7d8f9c4b8d-abc12    1/1     Running   0          15s
pod/vulntracker-api-7d8f9c4b8d-def45    1/1     Running   0          14s

NAME                        TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)
service/vulntracker-api     ClusterIP   10.96.123.456   <none>        8000/TCP

NAME                            READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/vulntracker-api 2/2     2            2           20s

NAME                                      DESIRED   CURRENT   READY   AGE
replicaset.apps/vulntracker-api-7d8f9c4b8d   2       2        2      20s

NAME                                    REFERENCE                   TARGETS         MINPODS   MAXPODS   REPLICAS   AGE
horizontalpodautoscaler.autoscaling/vulntracker-api   Deployment/vulntracker-api   <unknown>/80%   2         5         2          20s
```

**Success Criteria:**
- ✅ Pods reach "Running" status
- ✅ Both replicas started (minReplicas: 2)
- ✅ Service created
- ✅ HPA created

---

### 2.5 Check Pod Logs

**Command:**
```bash
kubectl logs -n vulntracker -l app=vulntracker-api --all-containers=true

# Or follow live logs
kubectl logs -f -n vulntracker -l app=vulntracker-api
```

**Expected Output:**
```
INFO:     Started server process [1]
INFO:     Waiting for application startup.
INFO:     Application startup complete
INFO:     Uvicorn running on http://0.0.0.0:8000
```

**Success Criteria:**
- ✅ No error logs
- ✅ Application startup completes
- ✅ Uvicorn listening on 0.0.0.0:8000

---

### 2.6 Test API Endpoints

**Command:**
```bash
# Port-forward to service
kubectl port-forward -n vulntracker svc/vulntracker-api 8000:8000 &

# Wait for connection
sleep 2

# Test health endpoint
curl http://localhost:8000/health

# Test API docs
curl http://localhost:8000/docs -I

# Stop port-forward
kill %1
```

**Expected Output:**
```
{"status":"ok"}
HTTP/1.1 200 OK
Content-type: text/html; charset=utf-8
```

**Success Criteria:**
- ✅ Health endpoint returns 200 OK
- ✅ API docs endpoint returns 200 OK
- ✅ Connection successful

---

### 2.7 Verify SecurityContext

**Command:**
```bash
# Get pod security context
kubectl get pod -n vulntracker -o json | \
  jq '.items[0].spec | {
    automountServiceAccountToken,
    securityContext,
    containers: [.containers[0].securityContext]
  }'
```

**Expected Output:**
```json
{
  "automountServiceAccountToken": false,
  "securityContext": {
    "runAsUser": 65532,
    "runAsGroup": 65532,
    "runAsNonRoot": true,
    "seccompProfile": {
      "type": "RuntimeDefault"
    }
  },
  "containers": [
    {
      "allowPrivilegeEscalation": false,
      "capabilities": {
        "drop": ["ALL"]
      },
      "readOnlyRootFilesystem": true
    }
  ]
}
```

**Success Criteria:**
- ✅ runAsUser: 65532
- ✅ runAsNonRoot: true
- ✅ allowPrivilegeEscalation: false
- ✅ capabilities.drop: ALL
- ✅ readOnlyRootFilesystem: true
- ✅ automountServiceAccountToken: false

---

### 2.8 Verify Read-Only Filesystem

**Command:**
```bash
# Try to write to root filesystem (should fail)
kubectl exec -n vulntracker deployment/vulntracker-api -- \
  touch /app/test.txt 2>&1

# Try to write to /tmp (should succeed)
kubectl exec -n vulntracker deployment/vulntracker-api -- \
  touch /tmp/test.txt 2>&1

# Verify file exists in /tmp
kubectl exec -n vulntracker deployment/vulntracker-api -- \
  ls -la /tmp/test.txt
```

**Expected Output:**
```
Read-only file system
/tmp/test.txt
-rw-r--r-- 1 nobody root 0 Jan 1 00:00 /tmp/test.txt
```

**Success Criteria:**
- ✅ Root filesystem is read-only (touch /app fails)
- ✅ /tmp is writable (tmpfs mount works)

---

### 2.9 Verify ServiceAccount Token NOT Mounted

**Command:**
```bash
# Check if token is mounted (should NOT exist)
kubectl exec -n vulntracker deployment/vulntracker-api -- \
  ls -la /var/run/secrets/kubernetes.io/serviceaccount/ 2>&1
```

**Expected Output:**
```
ls: cannot access '/var/run/secrets/kubernetes.io/serviceaccount/': No such file or directory
```

**Success Criteria:**
- ✅ ServiceAccount token directory does NOT exist
- ✅ Token mount is disabled (defense against RCE → lateral movement)

---

### 2.10 Verify NetworkPolicy

**Command:**
```bash
# Check NetworkPolicy exists
kubectl get networkpolicy -n vulntracker

# Describe policy
kubectl describe networkpolicy vulntracker-api -n vulntracker

# Show full policy
kubectl get networkpolicy -n vulntracker vulntracker-api -o yaml
```

**Expected Output:**
```
NAME              POD-SELECTOR                INGRESS   EGRESS   AGE
vulntracker-api   app=vulntracker-api,instance=vulntracker-api   2         2        40s

Policy Type:
  Ingress
  Egress

Ingress:
  from namespace: ingress-nginx, pod: ingress-nginx
  from pod: notify
  to port 8000/tcp

Egress:
  to pod: vulntracker-notify, port 3001/tcp
  to namespace: kube-system, port 53/udp, port 53/tcp
```

**Success Criteria:**
- ✅ NetworkPolicy created
- ✅ Ingress rules correct
- ✅ Egress rules correct
- ✅ DNS allowed (UDP/TCP 53)

---

### 2.11 Verify Resource Limits

**Command:**
```bash
# Check resource limits and requests
kubectl get pod -n vulntracker -o json | \
  jq '.items[0].spec.containers[0].resources'
```

**Expected Output:**
```json
{
  "limits": {
    "cpu": "500m",
    "memory": "512Mi"
  },
  "requests": {
    "cpu": "100m",
    "memory": "128Mi"
  }
}
```

**Success Criteria:**
- ✅ Limits: CPU 500m, Memory 512Mi
- ✅ Requests: CPU 100m, Memory 128Mi

---

### 2.12 Verify HPA Scaling

**Command:**
```bash
# Check HPA status
kubectl get hpa -n vulntracker
kubectl describe hpa vulntracker-api -n vulntracker

# Start load generator (in background)
kubectl run -n vulntracker load-gen \
  --image=curlimages/curl \
  -- sh -c "while true; do curl -s http://vulntracker-api:8000/health > /dev/null; done" &

# Monitor scaling (watch for replica count increase)
watch kubectl get hpa -n vulntracker

# After 1-2 minutes, should see replicas increase from 2 to 3+
# Stop load generator
kubectl delete pod -n vulntracker load-gen
```

**Expected Output:**
```
NAME              REFERENCE                   TARGETS         MINPODS   MAXPODS   REPLICAS   AGE
vulntracker-api   Deployment/vulntracker-api  25%/80%         2         5         2          2m

# After load...
vulntracker-api   Deployment/vulntracker-api  92%/80%         2         5         3          3m
```

**Success Criteria:**
- ✅ HPA created and active
- ✅ Replica count increases under load
- ✅ Scales between minReplicas (2) and maxReplicas (5)

---

## Cleanup

**Command:**
```bash
# Delete Helm release
helm uninstall vulntracker-api -n vulntracker

# Delete namespace
kubectl delete namespace vulntracker

# Stop minikube
minikube stop

# (Optional) Delete minikube
minikube delete
```

---

## Test Results Summary

| Test | Status | Notes |
|------|--------|-------|
| Cluster Start | ⚠️ PENDING | Run: `minikube start --cpus=4 --memory=4096` |
| Image Load | ⚠️ PENDING | Run: `docker build -t vulntracker-api:1.0.0 .` |
| Helm Deploy | ⚠️ PENDING | Expected: 2 replicas running |
| Pod Logs | ⚠️ PENDING | Expected: "Application startup complete" |
| Health Endpoint | ⚠️ PENDING | Expected: 200 OK |
| SecurityContext | ⚠️ PENDING | Expected: UID 65532, read-only FS |
| Token Isolation | ⚠️ PENDING | Expected: No token mounted |
| NetworkPolicy | ⚠️ PENDING | Expected: Policy enforced |
| Resource Limits | ⚠️ PENDING | Expected: CPU/memory limits applied |
| HPA Scaling | ⚠️ PENDING | Expected: Scales under load |

---

## Common Issues & Fixes

### Pod stuck in "Pending"
```bash
kubectl describe pod -n vulntracker <pod-name>
# Check: Resource availability, image pull errors
# Fix: minikube start --cpus=4 --memory=4096
```

### "ImagePullBackOff"
```bash
# Ensure image is in minikube's Docker
eval $(minikube docker-env)
docker images | grep vulntracker-api
# Redeploy with: --set image.pullPolicy=Never
```

### "Permission denied" on /tmp
```bash
# tmpfs not mounted
kubectl get pod -n vulntracker <pod-name> -o json | jq '.spec.volumes'
# Should include tmpfs volumes
```
