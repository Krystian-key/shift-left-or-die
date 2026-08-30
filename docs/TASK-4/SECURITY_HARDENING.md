# Container Security Hardening

This document outlines the security hardening measures implemented in the VulnTracker containerization.

## 0. Code Ownership Restriction (Critical)

### Problem
If the application process runs as `nonroot` but **owns the application code**, an attacker with RCE (Remote Code Execution) can modify the application files at runtime:
- Overwrite `main.py` or other modules
- Inject malicious code
- Maintain persistence across container restarts

### Solution
Ensure the application code is owned by `root:root` but readable by nonroot:

```dockerfile
COPY --chown=root:root --chmod=u=rwX,go=rX app/ .
```

**Permissions breakdown:**
- `u=rwX` — Owner (root): read, write, execute (X = execute only for directories)
- `go=rX` — Group & others (nonroot process): read & execute only, **NO write**

### Security Properties
- ✅ nonroot process can **read** code (needed to execute)
- ✅ nonroot process **cannot modify** code (RCE is contained)
- ✅ Only root can change code (requires container rebuild/redeploy)

**Benefit:** Limits blast radius of RCE attacks. Attacker cannot use code modification for persistence.

---

## Distroless User Selection

### Distroless UID Mapping
```
nonroot = 65532  ← Use this for general applications
nobody  = 65534  ← Traditional nobody user (avoid for containers)
```

We use **UID 65532** (Distroless `nonroot` user) because:
- Purpose-built for containerized applications
- Well-separated from host system users
- Officially recommended by Google Distroless
- Avoids confusion with system `nobody` (65534)

---

## 1. Dependency Path Resolution (Critical)

### Problem
When using distroless images with a non-root user, the standard `pip install --user` command places packages in the user's home directory (`/home/nonroot/.local`). The distroless `nonroot` user may not have:
- A properly configured `PYTHONPATH`
- Write permissions to the home directory
- Access to pip metadata

This can cause `ModuleNotFoundError` at runtime or force the application to run as root.

### Solution
Use `--prefix=/install` during the build stage and copy to `/usr/local` in the runtime stage:

```dockerfile
# Build stage
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Runtime stage
COPY --from=builder /install /usr/local
```

**Benefits:**
- Packages are in standard Python search path
- Owned by `root:root` (immutable by the application)
- Accessible by any user (including non-root)
- Prevents accidental package modification by compromised application

---

## 2. Read-Only Root Filesystem + Privilege Escalation Prevention

### Implementation

**Docker:**
```yaml
read_only: true
security_opt:
  - no-new-privileges:true
tmpfs:
  - /tmp
  - /var/tmp
cap_drop:
  - ALL
```

**Kubernetes:**
```yaml
securityContext:
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
```

### Security Properties

- **`read_only: true`** — Prevents write access to all directories except explicitly mounted tmpfs volumes. Stops malware from modifying binaries or configuration.
- **`no-new-privileges:true`** — Prevents processes from calling `exec()` on SUID/SGID binaries (e.g., `/usr/bin/sudo`, `/bin/su`). Blocks privilege escalation chains.
- **`cap_drop: ALL`** — Removes all Linux capabilities by default. Prevents use of privileged syscalls (e.g., `CAP_NET_RAW` for packet sniffing).
- **`tmpfs:/tmp`** — Provides a writable RAM-backed temporary directory for Python bytecode (`.pyc` files), needed by CPython. Lost on container restart.

### Trade-offs
- Applications requiring persistent `/tmp` must use an external volume or object storage.
- Debugging is harder (no write access to logs unless sent to stdout/stderr).

---

## 3. Separation of Concerns: Healthcheck

### Problem
Embedding an HTTP client library (e.g., `httpx`) in the container image for healthchecks creates a supply chain risk:
- If the application is compromised, the attacker has a pre-installed HTTP client to scan the internal network (SSRF).
- Extra dependencies increase attack surface.

### Solution
Move healthchecks to the orchestration layer:

**Kubernetes (Recommended):**
```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8000
  initialDelaySeconds: 10
  periodSeconds: 30
```

**Docker Compose:**
```yaml
healthcheck:
  test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"]
  interval: 30s
```

**Why this works:**
- Kubernetes and Docker handle probing externally.
- The container doesn't need `httpx` or `curl`.
- If the container is compromised, the attacker still has limited network tools.

---

## 4. User Namespaces (Host-Level Hardening)

### Problem
Even though the container runs as UID 65534 (`nonroot`), the host kernel still maps this to the actual `nobody` user on the host. If a container escapes, the attacker can modify files owned by `nobody` on the host filesystem.

### Solution
Enable user namespace remapping on the Docker daemon:

**File: `/etc/docker/daemon.json`**
```json
{
  "userns-remap": "default"
}
```

**Effect:**
- UID 65534 inside the container is mapped to (e.g.) UID 165534 on the host.
- A container breakout grants access to a non-existent or isolated UID on the host.
- Prevents horizontal privilege escalation across containers.

### Kubernetes
Kubernetes does not natively support userns-remap. Instead, use:
- **Pod Security Standards (PSS)** — Enforce `restricted` policy
- **Kubelet configuration** — Set `--userns-mode=pod` (Alpha feature)
- **seccomp profiles** — Restrict syscalls further

---

## 5. Image Verification

All base images are pinned to their SHA256 digest (not tags) to ensure reproducibility and prevent tag-swapping attacks:

```dockerfile
FROM python:3.11.16-slim@sha256:a3b79da6a2d8ea1e9f33eee8c968a21c2b9cffbffd13f8f70c5b69a5d5f5e5e5
FROM gcr.io/distroless/python3.11@sha256:e1acbd1a42c1cccaa35ed5889c71a6a1bf9a79ee4d3a48f34a3f4c1f3e1f3c1c
```

**Verification:**
```bash
# Using skopeo (no Docker daemon needed)
skopeo inspect docker://python:3.11.16-slim | jq '.Digest'

# Or with Docker
docker pull python:3.11.16-slim
docker inspect --format='{{.RepoDigests}}' python:3.11.16-slim
```

---

## 6. Distroless Image Benefits & Signal Handling

- **No shell** — `/bin/sh` is missing, preventing container escape via shell.
- **No package manager** — No `apt`, `apk`, or `yum`, preventing supply chain attacks.
- **Minimal libc** — Uses musl or no libc at all, reducing vulnerabilities in system libraries.
- **Smaller image size** — ~100 MB vs. 300+ MB for Alpine, reducing download/storage attack surface.

### Note on Signal Handling (vs. tini)

Hexops best practices recommend using `tini` as the ENTRYPOINT to handle signals and prevent zombie processes. However:

- **Distroless has no libc** — Cannot compile/include tini
- **Uvicorn handles signals natively** — Responds correctly to SIGTERM/SIGINT without tini
- **Read-only FS + security context** — Provides similar protection against accidental zombie processes

**Trade-off:** Distroless's minimal footprint and lack of shell outweigh tini's benefits for this application.

---

## Residual Risks & Mitigations

### Risk 1: Python Interpreter Compromise
**Mitigation:**
- Pin Python base image SHA
- Scan with vulnerability scanner (Grype, Trivy)
- Update regularly

### Risk 2: Application Code Vulnerabilities
**Mitigation:**
- SAST scanning (Semgrep)
- Dependency scanning (Grype)
- Code review before deployment

### Risk 3: Runtime Privilege Escalation (Kernel Bug)
**Mitigation:**
- Keep host kernel updated
- Use AppArmor/SELinux profiles in Kubernetes
- Enable seccomp filtering

### Risk 4: Network Attacks (SSRF, Port Scanning)
**Mitigation:**
- NetworkPolicy in Kubernetes
- Egress filtering via firewall
- Remove unnecessary network tools from image

---

## Deployment Checklist

- [ ] Base images pinned to SHA256 digests
- [ ] Dockerfile uses `--prefix=/install` for pip
- [ ] Container runs as UID 65534 (nonroot)
- [ ] No embedded secrets (loaded from secret manager)
- [ ] Healthcheck implemented at K8s/Docker Compose level
- [ ] `read_only: true` enforced
- [ ] `no-new-privileges: true` enforced
- [ ] `cap_drop: ALL` enforced
- [ ] `/tmp` and `/var/tmp` mounted as tmpfs
- [ ] Resource limits defined (CPU, memory)
- [ ] Network policies restrict ingress/egress
- [ ] Seccomp profiles applied
- [ ] Container scanned for vulnerabilities
- [ ] Regular image updates scheduled

---

## References

- [Distroless Images](https://github.com/GoogleContainerTools/distroless)
- [systemd UID/GID Allocation](https://github.com/systemd/systemd/blob/main/docs/UIDS-GIDS.md)
- [OWASP Container Security](https://owasp.org/www-project-container-security/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
