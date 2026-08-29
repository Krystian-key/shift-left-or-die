# Task 2 — Security Analysis Summary

## Scan Results Overview

| Scan Type | Tool | Format | Status |
|-----------|------|--------|--------|
| SAST | Semgrep | sast.semgrep.json | ✅ Complete |
| SBOM | Syft | sbom.cyclonedx.json | ✅ Complete |
| SCA | Grype | sca.grype.json | ✅ Complete |
| Container* | Trivy | container.trivy.json | ⏳ Task 4 |
| IaC* | Checkov | iac.checkov.json | ⏳ Task 4 |

## Vulnerability Summary

### SAST (Semgrep)
**Total Issues:** 3

### SCA (Grype)
**Total Vulnerabilities:** 65

**By Severity:**
- Critical: 2
- High: 26
- Medium: 22
- Low: 15

### SBOM (Syft)
**Format:** CycloneDX
**Status:** Complete dependency inventory

## File Access

All reports are human-readable (pretty-printed JSON):
- `sast.semgrep.json` — Source code security
- `sbom.cyclonedx.json` — Dependency BOM
- `sca.grype.json` — Known CVE vulnerabilities

