# Verifying Releases

Aldur releases include multiple layers of verification to ensure supply chain security.

## Quick Verification

### SHA-256 Checksums

Every release includes SHA-256 and SHA-512 checksums for all artifacts.

```bash
# Download checksums
curl -LO https://github.com/scovetta/aldur/releases/latest/download/checksums-sha256.txt

# Verify your downloaded file
sha256sum -c checksums-sha256.txt --ignore-missing
```

## Sigstore Cosign Verification

Checksums are signed using [Sigstore](https://www.sigstore.dev/) keyless signing, providing cryptographic proof that the release came from the official GitHub Actions workflow.

### Prerequisites

Install cosign: [https://docs.sigstore.dev/cosign/installation/](https://docs.sigstore.dev/cosign/installation/)

### Verify Signature

```bash
# Download signature and certificate
curl -LO https://github.com/scovetta/aldur/releases/latest/download/checksums-sha256.txt
curl -LO https://github.com/scovetta/aldur/releases/latest/download/checksums-sha256.txt.sig
curl -LO https://github.com/scovetta/aldur/releases/latest/download/checksums-sha256.txt.pem

# Verify the signature
cosign verify-blob \
  --signature checksums-sha256.txt.sig \
  --certificate checksums-sha256.txt.pem \
  --certificate-identity-regexp "https://github.com/scovetta/aldur/.*" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums-sha256.txt
```

If successful, you'll see:
```
Verified OK
```

## GitHub Attestations

Aldur uses [GitHub Artifact Attestations](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds) to provide cryptographic proof of where and how each release artifact was built.

### Prerequisites

Install the GitHub CLI: [https://cli.github.com/](https://cli.github.com/)

### Verify Build Provenance

```bash
# Download a release artifact
curl -LO https://github.com/scovetta/aldur/releases/latest/download/aldur-x86_64-unknown-linux-gnu.tar.gz

# Verify build provenance attestation
gh attestation verify aldur-x86_64-unknown-linux-gnu.tar.gz \
  --owner scovetta
```

If successful, you'll see details about the build including the commit, workflow, and runner.

### Verify SBOM Attestation

Each release also includes attested Software Bill of Materials (SBOM) in both SPDX and CycloneDX formats:

```bash
# Verify SPDX SBOM attestation
gh attestation verify aldur-x86_64-unknown-linux-gnu.tar.gz \
  --owner scovetta \
  --predicate-type https://spdx.dev/Document/v2.3

# Verify CycloneDX SBOM attestation
gh attestation verify aldur-x86_64-unknown-linux-gnu.tar.gz \
  --owner scovetta \
  --predicate-type https://cyclonedx.org/bom/v1.4
```

### View SBOM Contents from Attestation

You can extract and view the SBOM directly from the attestation:

```bash
# View SPDX SBOM from attestation
gh attestation verify aldur-x86_64-unknown-linux-gnu.tar.gz \
  --owner scovetta \
  --predicate-type https://spdx.dev/Document/v2.3 \
  --format json | jq '.[].verificationResult.statement.predicate'
```

## SBOM Files

Each release includes Software Bill of Materials files that list all dependencies:

| File | Format | Description |
|------|--------|-------------|
| `aldur-sbom.spdx.json` | SPDX 2.3 | ISO/IEC 5962:2021 standard |
| `aldur-sbom.cdx.json` | CycloneDX 1.4 | OWASP standard |

### Download SBOM

```bash
# Download SPDX SBOM
curl -LO https://github.com/scovetta/aldur/releases/latest/download/aldur-sbom.spdx.json

# Download CycloneDX SBOM
curl -LO https://github.com/scovetta/aldur/releases/latest/download/aldur-sbom.cdx.json
```

### Analyze SBOM for Vulnerabilities

You can use tools like [Grype](https://github.com/anchore/grype) to scan the SBOM for known vulnerabilities:

```bash
# Scan SBOM for vulnerabilities
grype sbom:aldur-sbom.spdx.json
```

## Complete Verification Script

Here's a complete script to download and verify a release:

```bash
#!/bin/bash
set -e

PLATFORM="x86_64-unknown-linux-gnu"
OWNER="scovetta"

echo "Downloading aldur for ${PLATFORM}..."
BASE_URL="https://github.com/${OWNER}/aldur/releases/latest/download"

curl -LO "${BASE_URL}/aldur-${PLATFORM}.tar.gz"
curl -LO "${BASE_URL}/checksums-sha256.txt"
curl -LO "${BASE_URL}/checksums-sha256.txt.sig"
curl -LO "${BASE_URL}/checksums-sha256.txt.pem"

echo "Verifying SHA-256 checksum..."
sha256sum -c checksums-sha256.txt --ignore-missing

echo "Verifying cosign signature..."
cosign verify-blob \
  --signature checksums-sha256.txt.sig \
  --certificate checksums-sha256.txt.pem \
  --certificate-identity-regexp "https://github.com/${OWNER}/aldur/.*" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums-sha256.txt

echo "Verifying GitHub attestation..."
gh attestation verify "aldur-${PLATFORM}.tar.gz" --owner "${OWNER}"

echo "✅ All verifications passed!"
echo "Extracting..."
tar -xzf "aldur-${PLATFORM}.tar.gz"
./aldur --version
```

## What Gets Verified?

| Verification | What It Proves |
|--------------|----------------|
| SHA-256 checksum | File integrity (not tampered) |
| Cosign signature | Checksums signed by official CI/CD |
| Build provenance | Binary built from official repo by GitHub Actions |
| SBOM attestation | Dependency list matches the binary |
