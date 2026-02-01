# Software Bill of Materials (SBOM)

Aldur releases include Software Bills of Materials (SBOMs) in multiple formats, providing transparency into the components and dependencies used in the tool.

## Available Formats

Each release includes SBOMs in two industry-standard formats:

### SPDX 2.3

The **Software Package Data Exchange (SPDX)** format is an ISO/IEC standard (ISO/IEC 5962:2021) for communicating software bill of material information.

- **File**: `aldur-sbom.spdx.json`
- **Standard**: SPDX 2.3
- **Format**: JSON

### CycloneDX 1.4

**CycloneDX** is an OWASP project providing a lightweight SBOM standard designed for use in application security contexts and supply chain component analysis.

- **File**: `aldur-sbom.cdx.json`
- **Standard**: CycloneDX 1.4
- **Format**: JSON

## Downloading SBOMs

SBOMs are attached to each GitHub release as assets:

```bash
# Download SPDX SBOM
gh release download v0.1.0 --pattern '*sbom.spdx.json'

# Download CycloneDX SBOM
gh release download v0.1.0 --pattern '*sbom.cdx.json'
```

Or download directly from the release page on GitHub.

## Verifying SBOMs

SBOMs are covered by the release attestations. You can verify them using GitHub's CLI:

```bash
# Download the SBOM files
gh release download v0.1.0 --pattern '*sbom*.json'

# Verify SBOM attestations
gh attestation verify aldur-sbom.spdx.json --repo scovetta/Aldur
gh attestation verify aldur-sbom.cdx.json --repo scovetta/Aldur
```

## Using SBOMs

### Vulnerability Scanning

Use SBOMs with vulnerability scanning tools:

```bash
# With grype (using CycloneDX)
grype sbom:aldur-sbom.cdx.json

# With trivy
trivy sbom aldur-sbom.spdx.json

# With syft
syft packages sbom:aldur-sbom.cdx.json
```

### License Compliance

Analyze licenses in the SBOM:

```bash
# With sbom-tool
sbom-tool validate -b aldur-sbom.spdx.json

# With ort (OSS Review Toolkit)
ort analyze -i aldur-sbom.spdx.json
```

### Dependency Analysis

View the dependency tree:

```bash
# Parse with jq
jq '.packages[] | {name, version: .versionInfo}' aldur-sbom.spdx.json

# For CycloneDX
jq '.components[] | {name, version}' aldur-sbom.cdx.json
```

## SBOM Contents

The SBOM includes:

- **Primary component**: Aldur binary
- **Direct dependencies**: Crates directly used by Aldur
- **Transitive dependencies**: All nested dependencies
- **Metadata**: Version, license, supplier information for each component

### Example Entry (SPDX)

```json
{
  "SPDXID": "SPDXRef-Package-crate-goblin-0.9.5",
  "name": "goblin",
  "versionInfo": "0.9.5",
  "downloadLocation": "https://crates.io/crates/goblin",
  "licenseDeclared": "MIT",
  "supplier": "Organization: crates.io"
}
```

### Example Entry (CycloneDX)

```json
{
  "type": "library",
  "name": "goblin",
  "version": "0.9.5",
  "purl": "pkg:cargo/goblin@0.9.5",
  "licenses": [{ "license": { "id": "MIT" } }]
}
```

## Integration with CI/CD

### Scanning in GitHub Actions

```yaml
- name: Download SBOM
  run: |
    gh release download ${{ github.event.release.tag_name }} \
      --pattern '*sbom.cdx.json'

- name: Scan for vulnerabilities
  uses: anchore/scan-action@v3
  with:
    sbom: aldur-sbom.cdx.json
    fail-build: true
    severity-cutoff: high
```

### Scanning in Azure Pipelines

```yaml
- script: |
    gh release download $(Build.BuildNumber) --pattern '*sbom.cdx.json'
    grype sbom:aldur-sbom.cdx.json --fail-on high
  displayName: 'Scan SBOM for vulnerabilities'
```

## Related

- [Release Verification](verification.md) - Verify release signatures and attestations
- [GitHub Action](../getting-started/github-action.md) - Use aldur in CI/CD
