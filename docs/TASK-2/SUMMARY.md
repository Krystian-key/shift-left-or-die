# Task 2 — Security Analysis Summary

## Scan Results Overview

| Scan Type | Tool | Format | Status |
|-----------|------|--------|--------|
| SAST | Semgrep | sast.semgrep.json | ✅ Complete |
| SCA SBOM | Syft | sbom.cyclonedx.json | ✅ Complete |
| SCA | Grype | sca.grype.json | ✅ Complete |
| Container SBOM | Syft | sbom.container.cyclonedx.json | ✅ Complete |
| Container Scan | Trivy | container.trivy.json | ✅ Complete |
| IaC Scan | Checkov | iac.checkov.json | ✅ Complete |

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
- `sast.semgrep.json` — Source code security (SAST)
- `sbom.cyclonedx.json` — Application dependency BOM
- `sca.grype.json` — Known CVE vulnerabilities in dependencies
- `sbom.container.cyclonedx.json` — Container image SBOM
- `container.trivy.json` — Container OS package vulnerabilities
- `iac.checkov.json` — Infrastructure-as-Code misconfigurations (Helm charts)

