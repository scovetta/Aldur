# Changelog

All notable changes to Aldur will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- GitHub Pages documentation site
- SBOM generation in SPDX and CycloneDX formats
- Sigstore cosign signing for release artifacts
- GitHub artifact attestations for build provenance
- Comprehensive security rule documentation

### Changed

- Enhanced Performance and Resolution sections in rule documentation

### Security

- Added supply chain security with artifact attestations
- Added SBOM attestations for dependency transparency

## [0.1.1] - Inital Public Release

### Added

- Initial release of Aldur
- PE (Windows) binary analysis
- ELF (Linux) binary analysis
- Mach-O (macOS) binary analysis
- SARIF output format
- GitHub Action for CI/CD integration
- Security profiles (minimal, standard, strict)
- Cross-platform support (Windows, Linux, macOS)
- ARM64 support

### Security Rules

#### PE (Windows)
- Control Flow Guard (CFG)
- Address Space Layout Randomization (ASLR)
- Stack protection (GS)
- Safe SEH
- High Entropy VA
- Authenticode signing
- And many more...

#### ELF (Linux)
- Position Independent Executable (PIE)
- Stack protector
- RELRO (full/partial)
- Non-executable stack
- FORTIFY_SOURCE
- And many more...

#### Mach-O (macOS)
- PIE
- Stack protector
- Code signing
- ARM64 PAC/BTI
- ARC (Objective-C)
- And many more...

---

For the full list of security rules, see the [Rules Reference](rules/index.md).

[Unreleased]: https://github.com/scovetta/Aldur/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/scovetta/Aldur/releases/tag/v0.1.1
