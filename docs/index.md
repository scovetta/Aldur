---
hide:
  - navigation
  - toc
---

<div class="hero" markdown>

# 🔒 Aldur

## Binary Security Analyzer

**Detect security vulnerabilities, misconfigurations, and missing hardening features in your binaries**

[Get Started :material-arrow-right:](getting-started/installation.md){ .md-button .md-button--primary }
[View on GitHub :material-github:](https://github.com/scovetta/aldur){ .md-button }

</div>

<div class="grid cards" markdown>

-   :material-file-search:{ .lg .middle } **Multi-Format Analysis**

    ---

    Analyze **PE** (Windows), **ELF** (Linux/Unix), and **Mach-O** (macOS) binaries with a single tool

-   :material-lightning-bolt:{ .lg .middle } **Blazing Fast**

    ---

    Written in Rust with parallel analysis — scan thousands of binaries in seconds

-   :material-shield-check:{ .lg .middle } **125+ Security Rules**

    ---

    Comprehensive checks for compiler flags, memory protections, and exploit mitigations

-   :material-laptop:{ .lg .middle } **Cross-Platform**

    ---

    Runs on Windows, Linux, and macOS with full PDB support on all platforms

</div>

---

## Quick Start

```bash
# Download and extract
curl -LO https://github.com/scovetta/Aldur/releases/download/v0.1.1/aldur-0.1.1-x86_64-unknown-linux-gnu.tar.gz
tar -xzf aldur-0.1.1-x86_64-unknown-linux-gnu.tar.gz

# Analyze a binary
./aldur analyze /path/to/binary

# Analyze a directory recursively with SARIF output
./aldur analyze -r -f sarif ./build/
```

<div class="grid cards" markdown>

-   :material-download:{ .lg .middle } **Download**

    ---

    [:fontawesome-brands-linux: Linux x64](https://github.com/scovetta/Aldur/releases/download/v0.1.1/aldur-0.1.1-x86_64-unknown-linux-gnu.tar.gz)
    [:fontawesome-brands-linux: Linux ARM64](https://github.com/scovetta/Aldur/releases/download/v0.1.1/aldur-0.1.1-aarch64-unknown-linux-gnu.tar.gz)

    [:fontawesome-brands-windows: Windows x64](https://github.com/scovetta/Aldur/releases/download/v0.1.1/aldur-0.1.1-x86_64-pc-windows-msvc.zip)
    [:fontawesome-brands-windows: Windows ARM64](https://github.com/scovetta/Aldur/releases/download/v0.1.1/aldur-0.1.1-aarch64-pc-windows-msvc.zip)

    [:fontawesome-brands-apple: macOS x64](https://github.com/scovetta/Aldur/releases/download/v0.1.1/aldur-0.1.1-x86_64-apple-darwin.tar.gz)
    [:fontawesome-brands-apple: macOS ARM64](https://github.com/scovetta/Aldur/releases/download/v0.1.1/aldur-0.1.1-aarch64-apple-darwin.tar.gz)

    [All Releases :material-arrow-right:](https://github.com/scovetta/Aldur/releases){ .md-button }

-   :material-github:{ .lg .middle } **GitHub Action**

    ---

    ```yaml
    - uses: scovetta/aldur@v1
      with:
        targets: './build/'
        upload-sarif: true
        fail-on-error: true
    ```

    [Action Documentation :material-arrow-right:](getting-started/github-action.md){ .md-button }

</div>

---

## Security Checks at a Glance

| Platform | Key Checks |
|:---------|:-----------|
| :fontawesome-brands-windows: **Windows PE** | ASLR, DEP, CFG, CET, /GS, /SDL, Authenticode, SafeSEH, High Entropy VA |
| :fontawesome-brands-linux: **Linux ELF** | PIE, RELRO, Stack Canary, FORTIFY_SOURCE, NX, BIND_NOW, CET, BTI/PAC |
| :fontawesome-brands-apple: **macOS Mach-O** | PIE, Stack Protector, ARC, Code Signing, PAC, Hardened Runtime |

[Browse All 125+ Rules :material-arrow-right:](rules/index.md){ .md-button }

---

## Why Aldur?

<div class="grid" markdown>

| Feature | Aldur | Other Tools |
|:--------|:-----:|:-----------:|
| Cross-platform binary | ✅ | ❌ Often platform-specific |
| PE + ELF + Mach-O | ✅ | ❌ Usually single format |
| PDB parsing (any OS) | ✅ | ❌ Windows-only |
| SARIF output | ✅ | ⚠️ Limited |
| GitHub Code Scanning | ✅ | ⚠️ Manual setup |
| Supply chain security | ✅ | ❌ Rarely signed |
| 125+ security rules | ✅ | ⚠️ Varies |

</div>

---

## Supply Chain Security

Every Aldur release includes:

- ✅ **SHA-256 checksums** for integrity verification
- ✅ **Sigstore cosign signatures** with keyless signing
- ✅ **GitHub artifact attestations** for build provenance
- ✅ **SBOM** in SPDX and CycloneDX formats

[Verify Your Download :material-arrow-right:](supply-chain/verification.md){ .md-button }
