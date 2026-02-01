# Aldur: A Comprehensive Binary Hardening Checker
<img align="left" width="200" height="200" src="logo.jpg" />

Aldur is a high-performance, cross-platform binary security analyzer written in Rust. It inspects PE (Windows), ELF (Linux/Unix), and Mach-O (macOS) binaries for security vulnerabilities, misconfigurations, and missing hardening features, and is aware of MSVC, gcc, Clang, and Rust compilers.

[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Latest release](https://img.shields.io/github/v/release/scovetta/aldur)](/scovetta/Aldur/releases/)

## Features

- 🔍 **Multi-format support**: Analyzes PE, ELF, and Mach-O binaries
- ⚡ **High performance**: Written in Rust with parallel analysis support
- 📊 **Useful output**: Static Analysis Results Interchange Format (SARIF) or text output
- 🔒 **Comprehensive security checks**: 125+ security rules covering compiler flags, memory protections, and exploit mitigations
- 🖥️ **Cross-platform**: Runs on Windows, Linux, and macOS
- 🔧 **PDB support**: Cross-platform Windows PDB analysis (no Windows SDK required)
- 📁 **Flexible input**: Analyze individual files, directories, archives, or glob patterns

## Installation

### Pre-built Binaries

Download pre-built binaries from the [Releases](https://github.com/scovetta/aldur/releases) page:

| Platform | Architecture | File |
|----------|--------------|------|
| Linux (glibc) | x86_64 | `aldur-*-x86_64-unknown-linux-gnu.tar.gz` |
| Linux (musl) | x86_64 | `aldur-*-x86_64-unknown-linux-musl.tar.gz` |
| Linux | ARM64 | `aldur-*-aarch64-unknown-linux-gnu.tar.gz` |
| Windows | x86_64 | `aldur-*-x86_64-pc-windows-msvc.zip` |
| macOS | x86_64 | `aldur-*-x86_64-apple-darwin.tar.gz` |
| macOS | ARM64 (Apple Silicon) | `aldur-*-aarch64-apple-darwin.tar.gz` |

### Verify Release Integrity

All releases include checksums, signatures, and attestations for supply chain security:

```bash
# Verify SHA-256 checksum
curl -LO https://github.com/scovetta/aldur/releases/latest/download/checksums-sha256.txt
sha256sum -c checksums-sha256.txt --ignore-missing

# Verify cosign signature (requires cosign)
cosign verify-blob \
  --signature checksums-sha256.txt.sig \
  --certificate checksums-sha256.txt.pem \
  --certificate-identity-regexp "https://github.com/scovetta/aldur/.*" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums-sha256.txt

# Verify GitHub build attestation (requires gh CLI)
gh attestation verify aldur-*-x86_64-unknown-linux-gnu.tar.gz --owner scovetta

# Verify SBOM attestation
gh attestation verify aldur-*-x86_64-unknown-linux-gnu.tar.gz \
  --owner scovetta \
  --predicate-type https://spdx.dev/Document/v2.3
```

See [Supply Chain Verification](https://scovetta.github.io/aldur/supply-chain/verification/) for complete details.

### Build From Source

```bash
git clone https://github.com/scovetta/aldur
cd aldur/src
cargo build --release
```

The binary will be available at `target/release/aldur`.


### Requirements

- Rust 1.70 or later (for building from source)
- No external runtime dependencies (PDB parsing works cross-platform)

## GitHub Action

Aldur is available as a GitHub Action for easy integration into CI/CD pipelines.

### Basic Usage

```yaml
- name: Run aldur security scan
  uses: scovetta/aldur@v1
  with:
    targets: 'path/to/binaries'
```

### Full Example

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    steps:
      - uses: actions/checkout@8e8c483db84b4bee98b60c0593521ed34d9990e8 # v6.0.1
        with:
          persist-credentials: false

      - name: Build project
        run: cargo build --release

      - name: Run aldur
        uses: scovetta/aldur@v1
        with:
          targets: 'target/release'
          format: sarif
          output: results.sarif
          recurse: true
          upload-sarif: true
          fail-on-error: true
```

### Action Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `targets` | Files, directories, or glob patterns to analyze (required) | - |
| `output` | Output file path for results | `aldur-results.sarif` |
| `format` | Output format: `sarif`, `text`, `text-color` | `sarif` |
| `recurse` | Recurse into subdirectories | `true` |
| `show-passed` | Include passing rules in output | `false` |
| `level` | Minimum failure level (`error`, `warning`, `note`) | - |
| `scan-archives` | Scan binaries inside archives (ZIP, TAR, APK, etc.) | `true` |
| `version` | aldur version to use | `latest` |
| `upload-sarif` | Upload SARIF results to GitHub Code Scanning | `true` |
| `fail-on-error` | Fail the workflow if errors are found | `true` |

### Action Outputs

| Output | Description |
|--------|-------------|
| `sarif-file` | Path to the generated SARIF file |
| `errors` | Number of errors found |
| `warnings` | Number of warnings found |
| `files-analyzed` | Number of files analyzed |

## Quick Start

### Analyze a single binary

```bash
aldur analyze /path/to/binary
```

### Analyze a directory recursively

```bash
aldur analyze -r /path/to/binaries/
```

### Analyze binaries inside an archive

```bash
# Scan APK, IPA, MSIX, ZIP, TAR, 7z, JAR, and more
aldur analyze app.apk
aldur analyze release.tar.gz
aldur analyze package.msix

# Disable archive scanning
aldur analyze --scan-archives=false archive.zip
```

### Save results to a SARIF file

```bash
aldur analyze -o results.sarif /path/to/binary
```

### Analyze with verbose output

```bash
aldur -v analyze /path/to/binary
```

## Usage

```
aldur [OPTIONS] <COMMAND>

Commands:
  analyze        Analyze binary files for security issues
  export-rules   Export rules metadata as JSON
  export-config  Export configuration template
  dump           Dump binary information (headers, sections, etc.)
  help           Print help information

Options:
  -v, --verbose  Enable verbose output
  -h, --help     Print help
  -V, --version  Print version
```

### Analyze Command Options

```
aldur analyze [OPTIONS] <TARGETS>...

Arguments:
  <TARGETS>...  Files, directories, or glob patterns to analyze

Options:
  -o, --output <OUTPUT>          Output file path for SARIF results
  -P, --profile <PROFILE>        Security profile (default, strict, relaxed, android, rhel, fips)
  -r, --recurse                  Recurse into subdirectories
  -c, --config <CONFIG>          Path to configuration file
  -q, --quiet                    Suppress console output
  -s, --statistics               Generate timing statistics
  -v, --verbose                  Enable verbose output
      --sympath <SYMPATH>        Symbol path for PDB lookup
      --level <LEVEL>            Failure levels to include (Error, Warning, Note)
      --baseline <BASELINE>      Baseline SARIF file for comparison
      --save-baseline <FILE>     Save current results as a baseline
      --summary                  Show multi-target summary report
      --max-file-size-kb <SIZE>  Maximum file size in KB (0 = unlimited)
      --threads <N>              Number of threads (0 = auto)
      --scan-archives            Scan contents of archives (default: true)
      --scan-nested-archives     Scan nested archives within archives (default: true)
      --max-archive-depth <N>    Maximum archive extraction depth (default: 3)
      --max-archive-size-mb <MB> Maximum uncompressed size in MB (default: 10240)
      --max-archive-entries <N>  Maximum entries to extract (default: 100000)
      --include <RULES>          Comma-separated list of rule IDs to include (overrides profile)
      --exclude <RULES>          Comma-separated list of rule IDs to exclude (overrides profile)
      --custom-profiles <PATH>   Path to custom profiles file
  -h, --help                     Print help
```

### Security Profiles

Profiles provide predefined configurations for different security requirements. Rules are tagged with semantic labels (e.g., `critical`, `memory-safety`, `intel-only`), and profiles filter rules based on these tags.

| Profile | Description | Use Case |
|---------|-------------|----------|
| `default` | Critical and recommended security checks | General-purpose scanning |
| `strict` | All security rules elevated to error (includes hardening) | High-security environments |
| `relaxed` | Only critical security checks | Legacy/compatibility scanning |
| `openssf` | OpenSSF Compiler Hardening Guide compliance | Standards compliance |
| `android` | Android CDD requirements, excludes Intel-specific | Android app/library development |
| `rhel` | Red Hat annocheck-compatible | RHEL/Fedora package builds |
| `fips` | FIPS 140-2/3 compliance focus | Government/regulated environments |
| `nightly` | All checks including Rust nightly requirements | Development with Rust nightly |
| `optimization` | Performance and binary size optimization | Build optimization validation |

The `default` profile focuses on essential security checks. It excludes:
- **Hardening rules** (Spectre mitigations, SafeStack, CFI, etc.) — use `strict` profile for these
- **Debug-only rules** (ASan, UBSan) — these check for sanitizer presence in debug builds
- **Optimization rules** (LTCG, COMDAT folding, etc.) — use `optimization` profile for these
- **Nightly rules** — require Rust nightly compiler

The `openssf` profile enforces the [OpenSSF Compiler Options Hardening Guide for C and C++](https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html), checking for:
- Position Independent Executable (PIE)
- Non-executable stack
- Stack protector (canary)
- Stack clash protection
- Full RELRO with immediate binding
- Control-flow protection (CET on Intel, BTI/PAC on ARM)
- FORTIFY_SOURCE usage
- Exception handling frames
- Restricted dlopen() for shared libraries

```bash
# Use strict profile for CI/CD
aldur analyze --profile strict ./build/

# Use openssf profile for compliance checking
aldur analyze --profile openssf ./build/

# Use android profile for mobile libraries
aldur analyze --profile android ./libs/

# List available profiles
aldur list-profiles
```

#### Rule Inclusion/Exclusion

You can override any profile by explicitly including or excluding specific rules:

```bash
# Add specific rules to a profile
aldur analyze --profile relaxed --include AD3033,AD3035,AD3037 ./build/

# Exclude rules from a profile
aldur analyze --profile strict --exclude AD2041,AD2045,AD2046 ./build/

# Combine both
aldur analyze --profile default --include AD3033 --exclude AD2024 ./build/
```

### Custom Profiles

For advanced use cases, you can define custom profiles in a file. Custom profiles can inherit from built-in profiles and add or remove specific rules.

#### Custom Profile File Format

```ini
# Comments start with # or ;
# Each profile is defined with [profile_name]

[minimal]
# No base profile = only explicitly included rules
+AD3001
+AD3002
+AD3003

[nightly_rust]
# Start with default profile
profile:default
# Add nightly/experimental rules
+AD3033
+AD3035
+AD3037

[strict_no_sanitizers]
# Start with strict profile
profile:strict
# Remove sanitizer rules (for production builds)
-AD2041
-AD2045
-AD2046
-AD3041
-AD3045
```

#### Profile Directives

| Directive | Description |
|-----------|-------------|
| `[name]` | Defines a new profile with the given name |
| `profile:base` | Inherit from a built-in profile (default, strict, relaxed, etc.) |
| `+ADXXXX` | Include the specified rule (overrides base exclusions) |
| `-ADXXXX` | Exclude the specified rule (overrides base inclusions) |

#### Using Custom Profiles

```bash
# Use a custom profile from file
aldur analyze --custom-profiles=my_profiles.txt --profile=minimal ./build/

# Custom profiles file can contain multiple profiles
aldur analyze --custom-profiles=profiles.txt --profile=nightly_rust ./build/

# Built-in profiles still work when a custom profiles file is loaded
aldur analyze --custom-profiles=profiles.txt --profile=strict ./build/
```

### Archive Scanning

Aldur can scan binaries inside archive files, making it easy to analyze packaged applications, mobile apps, and release artifacts without manual extraction.

#### Supported Archive Formats

| Format | Extensions | Description |
|--------|------------|-------------|
| ZIP | `.zip` | Standard ZIP archives |
| Java | `.jar`, `.war`, `.ear` | Java archives |
| Android | `.apk` | Android application packages |
| iOS | `.ipa` | iOS application packages |
| Windows | `.msix`, `.msixbundle`, `.appx`, `.appxbundle` | Windows app packages |
| NuGet | `.nupkg` | .NET packages |
| Browser | `.xpi`, `.crx` | Firefox/Chrome extensions |
| TAR | `.tar` | Uncompressed tape archives |
| Gzip | `.tar.gz`, `.tgz` | Gzip-compressed tar |
| Bzip2 | `.tar.bz2`, `.tbz2` | Bzip2-compressed tar |
| XZ | `.tar.xz`, `.txz` | XZ-compressed tar |
| 7-Zip | `.7z` | 7-Zip archives |
| macOS | `.app` (directories) | Apple app bundles |

#### Archive Scanning Options

```bash
# Scan an Android APK
aldur analyze myapp.apk

# Scan an iOS app
aldur analyze myapp.ipa

# Scan Windows MSIX package
aldur analyze myapp.msix

# Scan a release tarball
aldur analyze release-1.0.0.tar.gz

# Disable archive scanning
aldur analyze --scan-archives=false packages/

# Limit nesting depth (default: 3)
aldur analyze --max-archive-depth 1 nested.zip

# Limit extraction size (default: 10GB)
aldur analyze --max-archive-size-mb 1024 large.tar.gz
```

#### Security Considerations

Archive scanning uses a temporary directory for extraction. The following safeguards are in place:
- **Depth limiting**: Prevents zip-bomb attacks via nested archives (default: 3 levels)
- **Size limiting**: Caps total uncompressed size (default: 10GB)
- **Entry limiting**: Caps number of files extracted (default: 100,000)
- **Path sanitization**: Prevents path traversal attacks (e.g., `../../../etc/passwd`)
- **Automatic cleanup**: Temporary files are deleted after scanning

### Baseline Comparison

Compare new scans against a baseline to track security posture over time:

```bash
# Save current results as a baseline
aldur analyze --save-baseline baseline.json ./build/

# Compare against baseline (only show new issues)
aldur analyze --baseline baseline.json ./build/

# In CI: fail only on NEW issues, not existing ones
aldur analyze --baseline baseline.json --new-only ./build/
```

## Security Rules

Aldur implements comprehensive security rules organized by binary format.

> **Note on compiler columns:** Rules marked for specific compilers check features unique to that toolchain. For PE binaries, MSVC-only rules (like `/GS`, `/Qspectre`, `/sdl`) require PDB files containing MSVC-specific metadata. Clang-cl on Windows can produce PDB files but doesn't implement these MSVC-specific flags. GCC/MinGW uses DWARF debugging even on Windows and cannot produce PDB files. Rules checking binary-level properties (like ASLR, NX, CFG flags in the PE header) apply to all compilers that can set those flags.

### PE (Windows) Rules — 54 rules

| Rule ID | Name | Category | MSVC | Clang | Rust | .NET |
|---------|------|----------|:----:|:-----:|:----:|:----:|
| AD2001 | [LoadImagesAboveFourGigabyteAddress](docs/rules/AD2001.LoadImagesAboveFourGigabyteAddress.md) | Security | ✓ | ✓ | ✓ | ✓ |
| AD2004 | [EnableSecureSourceCodeHashing](docs/rules/AD2004.EnableSecureSourceCodeHashing.md) | Security | ✓ | ✗ | ✗ | ✗ |
| AD2006 | [BuildWithSecureTools](docs/rules/AD2006.BuildWithSecureTools.md) | Security | ✓ | ✗ | ✗ | ✗ |
| AD2007 | [EnableCriticalCompilerWarnings](docs/rules/AD2007.EnableCriticalCompilerWarnings.md) | Security | ✓ | ✗ | ✗ | ✗ |
| AD2008 | [EnableControlFlowGuard](docs/rules/AD2008.EnableControlFlowGuard.md) | Security | ✓ | ✓ | ✓ | ✗ |
| AD2009 | [EnableAddressSpaceLayoutRandomization](docs/rules/AD2009.EnableAddressSpaceLayoutRandomization.md) | Security | ✓ | ✓ | ✓ | ✓ |
| AD2010 | [DoNotMarkImportsSectionAsExecutable](docs/rules/AD2010.DoNotMarkImportsSectionAsExecutable.md) | Security | ✓ | ✓ | ✓ | ✓ |
| AD2011 | [EnableStackProtection](docs/rules/AD2011.EnableStackProtection.md) | Security | ✓ | ✗ | ✗ | ✗ |
| AD2012 | [DoNotModifyStackProtectionCookie](docs/rules/AD2012.DoNotModifyStackProtectionCookie.md) | Security | ✓ | ✗ | ✗ | ✗ |
| AD2013 | [InitializeStackProtection](docs/rules/AD2013.InitializeStackProtection.md) | Security | ✓ | ✗ | ✗ | ✗ |
| AD2014 | [DoNotDisableStackProtectionForFunctions](docs/rules/AD2014.DoNotDisableStackProtectionForFunctions.md) | Security | ✓ | ✗ | ✗ | ✗ |
| AD2015 | [EnableHighEntropyVirtualAddresses](docs/rules/AD2015.EnableHighEntropyVirtualAddresses.md) | Security | ✓ | ✓ | ✓ | ✓ |
| AD2016 | [MarkImageAsNXCompatible](docs/rules/AD2016.MarkImageAsNXCompatible.md) | Security | ✓ | ✓ | ✓ | ✓ |
| AD2018 | [EnableSafeSEH](docs/rules/AD2018.EnableSafeSEH.md) | Security | ✓ | ✗ | ✗ | ✗ |
| AD2019 | [DoNotMarkWritableSectionsAsShared](docs/rules/AD2019.DoNotMarkWritableSectionsAsShared.md) | Security | ✓ | ✓ | ✓ | ✓ |
| AD2021 | [DoNotMarkWritableSectionsAsExecutable](docs/rules/AD2021.DoNotMarkWritableSectionsAsExecutable.md) | Security | ✓ | ✓ | ✓ | ✓ |
| AD2024 | [EnableSpectreMitigations](docs/rules/AD2024.EnableSpectreMitigations.md) | Security | ✓ | ✗ | ✗ | ✗ |
| AD2025 | [EnableShadowStack](docs/rules/AD2025.EnableShadowStack.md) | Security | ✓ | ✓ | ✓ | ✗ |
| AD2026 | [EnableMicrosoftCompilerSdlSwitch](docs/rules/AD2026.EnableMicrosoftCompilerSdlSwitch.md) | Security | ✓ | ✗ | ✗ | ✗ |
| AD2027 | [EnableSourceLink](docs/rules/AD2027.EnableSourceLink.md) | Debugging | ✓ | ✗ | ✗ | ✓ |
| AD2029 | [EnableIntegrityCheck](docs/rules/AD2029.EnableIntegrityCheck.md) | Security | ✓ | ✓ | ✓ | ✓ |
| AD2030 | [EnableCastGuard](docs/rules/AD2030.EnableCastGuard.md) | Security | ✓ | ✗ | ✗ | ✗ |
| AD2031 | [EnableControlStackChecking](docs/rules/AD2031.EnableControlStackChecking.md) | Security | ✓ | ✗ | ✗ | ✗ |
| AD2032 | [DotNetEnableHighEntropyVA](docs/rules/AD2032.DotNetEnableHighEntropyVA.md) | Security | ✗ | ✗ | ✗ | ✓ |
| AD4001 | [ReportPECompilerData](docs/rules/AD4001.ReportPECompilerData.md) | Reporting | ✓ | ✓ | ✓ | ✓ |
| AD6001 | [DisableIncrementalLinkingInReleaseBuilds](docs/rules/AD6001.DisableIncrementalLinkingInReleaseBuilds.md) | Performance | ✓ | ✗ | ✗ | ✗ |
| AD6002 | [EliminateDuplicateStrings](docs/rules/AD6002.EliminateDuplicateStrings.md) | Performance | ✓ | ✗ | ✗ | ✗ |
| AD6004 | [EnableComdatFolding](docs/rules/AD6004.EnableComdatFolding.md) | Performance | ✓ | ✓ | ✗ | ✗ |
| AD6005 | [EnableOptimizeReferences](docs/rules/AD6005.EnableOptimizeReferences.md) | Performance | ✓ | ✓ | ✗ | ✗ |
| AD6006 | [EnableLinkTimeCodeGeneration](docs/rules/AD6006.EnableLinkTimeCodeGeneration.md) | Performance | ✓ | ✓ | ✓ | ✗ |

#### Additional PE Rules (Clang/Rust/DWARF)

| Rule ID | Name | Category | Clang | Rust |
|---------|------|----------|:-----:|:----:|
| AD2033 | [PeEnableStackProtectorDwarf](docs/rules/AD2033.PeEnableStackProtectorDwarf.md) | Security | ✓ | ✗ |
| AD2034 | [PeEnableLtoDwarf](docs/rules/AD2034.PeEnableLtoDwarf.md) | Security | ✓ | ✓ |
| AD2035 | [PeReportCompilerDataDwarf](docs/rules/AD2035.PeReportCompilerDataDwarf.md) | Reporting | ✓ | ✓ |
| AD2036 | [PeEnableControlFlowIntegrity](docs/rules/AD2036.PeEnableControlFlowIntegrity.md) | Security | ✓ | ✗ |
| AD2037 | [PeEnableStackClashProtection](docs/rules/AD2037.PeEnableStackClashProtection.md) | Security | ✓ | ✗ |
| AD2038 | [PeEnableClangSafeStack](docs/rules/AD2038.PeEnableClangSafeStack.md) | Security | ✓ | ✗ |
| AD2039 | [PeEnableArmPAC](docs/rules/AD2039.PeEnableArmPAC.md) | Security | ✓ | ✓ |
| AD2040 | [PeEnableArmBTI](docs/rules/AD2040.PeEnableArmBTI.md) | Security | ✓ | ✓ |
| AD2041 | [RustEnableSanitizersPE](docs/rules/AD2041.RustEnableSanitizersPE.md) | Security | ✗ | ✓ |
| AD2042 | [NoUnicodeSymbolsPE](docs/rules/AD2042.NoUnicodeSymbolsPE.md) | Security | ✓ | ✓ |
| AD2043 | [DoNotUseBannedApisPE](docs/rules/AD2043.DoNotUseBannedApisPE.md) | Security | ✓ | ✗ |
| AD2044 | [DoNotStaticallyLinkOpenSSLPE](docs/rules/AD2044.DoNotStaticallyLinkOpenSSLPE.md) | Security | ✓ | ✓ |
| AD2045 | [EnableUBSanPE](docs/rules/AD2045.EnableUBSanPE.md) | Security | ✓ | ✗ |
| AD2046 | [EnableAddressSanitizerPE](docs/rules/AD2046.EnableAddressSanitizerPE.md) | Security | ✓ | ✗ |
| AD2047 | [PeEnableShadowCallStack](docs/rules/AD2047.PeEnableShadowCallStack.md) | Security | ✓ | ✗ |
| AD2048 | [PeEnableStackVariableInitialization](docs/rules/AD2048.PeEnableStackVariableInitialization.md) | Security | ✓ | ✗ |
| AD2050 | [DoNotUseCustomBaseAddress](docs/rules/AD2050.DoNotUseCustomBaseAddress.md) | Security | ✓ | ✓ |
| AD2051 | [CheckMinimumLibraryVersions](docs/rules/AD2051.CheckMinimumLibraryVersions.md) | Security | ✓ | ✓ |
| AD2052 | [RequireAuthenticode](docs/rules/AD2052.RequireAuthenticode.md) | Security | ✓ | ✓ |
| AD2053 | [AllowIsolation](docs/rules/AD2053.AllowIsolation.md) | Security | ✓ | ✓ |
| AD2054 | [EnableReturnFlowGuard](docs/rules/AD2054.EnableReturnFlowGuard.md) | Security | ✓ | ✓ |
| AD2060 | [DetectPackedBinary](docs/rules/AD2060.DetectPackedBinary.md) | Security | ✓ | ✓ |
| AD3034 | [RustEnableControlFlowGuard](docs/rules/AD3034.RustEnableControlFlowGuard.md) | Security | ✗ | ✓ |

### ELF (Linux/Unix) Rules — 41 rules

| Rule ID | Name | Category | GCC | Clang | Rust |
|---------|------|----------|:---:|:-----:|:----:|
| AD3001 | [EnablePositionIndependentExecutable](docs/rules/AD3001.EnablePositionIndependentExecutable.md) | Security | ✓ | ✓ | ✓ |
| AD3002 | [DoNotMarkStackAsExecutable](docs/rules/AD3002.DoNotMarkStackAsExecutable.md) | Security | ✓ | ✓ | ✓ |
| AD3003 | [EnableStackProtector](docs/rules/AD3003.EnableStackProtector.md) | Security | ✓ | ✓ | ✗ |
| AD3004 | [GenerateRequiredSymbolFormat](docs/rules/AD3004.GenerateRequiredSymbolFormat.md) | Debugging | ✓ | ✓ | ✓ |
| AD3005 | [EnableStackClashProtection](docs/rules/AD3005.EnableStackClashProtection.md) | Security | ✓ | ✓ | ✗ |
| AD3006 | [EnableNonExecutableStack](docs/rules/AD3006.EnableNonExecutableStack.md) | Security | ✓ | ✓ | ✓ |
| AD3010 | [EnableReadOnlyRelocations](docs/rules/AD3010.EnableReadOnlyRelocations.md) | Security | ✓ | ✓ | ✓ |
| AD3011 | [EnableBindNow](docs/rules/AD3011.EnableBindNow.md) | Security | ✓ | ✓ | ✓ |
| AD3012 | [DoNotUseRpath](docs/rules/AD3012.DoNotUseRpath.md) | Security | ✓ | ✓ | ✓ |
| AD3013 | [ValidateRunpath](docs/rules/AD3013.ValidateRunpath.md) | Security | ✓ | ✓ | ✓ |
| AD3014 | [NoTextRelocations](docs/rules/AD3014.NoTextRelocations.md) | Security | ✓ | ✓ | ✓ |
| AD3015 | [EnableIntelCET](docs/rules/AD3015.EnableIntelCET.md) | Security | ✓ | ✓ | ✓ |
| AD3016 | [EnableIntelShadowStack](docs/rules/AD3016.EnableIntelShadowStack.md) | Security | ✓ | ✓ | ✓ |
| AD3017 | [EnableArmBTI](docs/rules/AD3017.EnableArmBTI.md) | Security | ✓ | ✓ | ✓ |
| AD3018 | [EnableArmPAC](docs/rules/AD3018.EnableArmPAC.md) | Security | ✓ | ✓ | ✓ |
| AD3019 | [EnableLTO](docs/rules/AD3019.EnableLTO.md) | Performance | ✓ | ✓ | ✓ |
| AD3020 | [EnableOptimization](docs/rules/AD3020.EnableOptimization.md) | Performance | ✓ | ✓ | ✓ |
| AD3021 | [NoUnicodeSymbols](docs/rules/AD3021.NoUnicodeSymbols.md) | Security | ✓ | ✓ | ✓ |
| AD3022 | [WritableGotProtection](docs/rules/AD3022.WritableGotProtection.md) | Security | ✓ | ✓ | ✓ |
| AD3023 | [ProperLoadSegments](docs/rules/AD3023.ProperLoadSegments.md) | Security | ✓ | ✓ | ✓ |
| AD3024 | [RestrictDlopen](docs/rules/AD3024.RestrictDlopen.md) | Security | ✓ | ✓ | ✓ |
| AD3025 | [EnableExceptionHandling](docs/rules/AD3025.EnableExceptionHandling.md) | Security | ✓ | ✓ | ✓ |
| AD3030 | [UseGccCheckedFunctions](docs/rules/AD3030.UseGccCheckedFunctions.md) | Security | ✓ | ✓ | ✗ |
| AD3031 | [EnableClangSafeStack](docs/rules/AD3031.EnableClangSafeStack.md) | Security | ✗ | ✓ | ✗ |
| AD3032 | [EnableSpeculativeLoadHardening](docs/rules/AD3032.EnableSpeculativeLoadHardening.md) | Security | ✗ | ✓ | ✗ |
| AD3033 | [RustEnableCET](docs/rules/AD3033.RustEnableCET.md) | Security | ✗ | ✗ | ✓ |
| AD3034 | [RustEnableControlFlowGuard](docs/rules/AD3034.RustEnableControlFlowGuard.md) | Security | ✗ | ✗ | ✓ |
| AD3035 | [RustEnableSecureSourceHash](docs/rules/AD3035.RustEnableSecureSourceHash.md) | Security | ✗ | ✗ | ✓ |
| AD3036 | [EnableControlFlowIntegrity](docs/rules/AD3036.EnableControlFlowIntegrity.md) | Security | ✗ | ✓ | ✗ |
| AD3037 | [RustEnableSanitizers](docs/rules/AD3037.RustEnableSanitizers.md) | Security | ✗ | ✗ | ✓ |
| AD3038 | [EnableUBSan](docs/rules/AD3038.EnableUBSan.md) | Security | ✓ | ✓ | ✗ |
| AD3039 | [EnableArmMTE](docs/rules/AD3039.EnableArmMTE.md) | Security | ✓ | ✓ | ✓ |
| AD3040 | [EnableAddressSanitizerELF](docs/rules/AD3040.EnableAddressSanitizerELF.md) | Security | ✓ | ✓ | ✗ |
| AD3041 | [DoNotUseBannedApisELF](docs/rules/AD3041.DoNotUseBannedApisELF.md) | Security | ✓ | ✓ | ✗ |
| AD3042 | [DoNotStaticallyLinkOpenSSLELF](docs/rules/AD3042.DoNotStaticallyLinkOpenSSLELF.md) | Security | ✓ | ✓ | ✓ |
| AD3043 | [EnableKernelCFI](docs/rules/AD3043.EnableKernelCFI.md) | Security | ✗ | ✓ | ✗ |
| AD3044 | [EnableShadowCallStack](docs/rules/AD3044.EnableShadowCallStack.md) | Security | ✗ | ✓ | ✗ |
| AD3045 | [EnableStackVariableInitialization](docs/rules/AD3045.EnableStackVariableInitialization.md) | Security | ✗ | ✓ | ✗ |
| AD3050 | [EnableGccDefs](docs/rules/AD3050.EnableGccDefs.md) | Security | ✓ | ✓ | ✗ |
| AD3051 | [CheckFortifySourceLevel](docs/rules/AD3051.CheckFortifySourceLevel.md) | Security | ✓ | ✓ | ✗ |
| AD3060 | [DetectPackedBinary](docs/rules/AD3060.DetectPackedBinary.md) | Security | ✓ | ✓ | ✓ |
| AD4002 | [ReportElfOrMachoCompilerData](docs/rules/AD4002.ReportElfOrMachoCompilerData.md) | Reporting | ✓ | ✓ | ✓ |

### Mach-O (macOS) Rules — 32 rules

| Rule ID | Name | Category | Clang | Rust | Swift |
|---------|------|----------|:-----:|:----:|:-----:|
| AD5001 | [EnablePositionIndependentExecutableMachO](docs/rules/AD5001.EnablePositionIndependentExecutableMachO.md) | Security | ✓ | ✓ | ✓ |
| AD5002 | [DoNotAllowExecutableStack](docs/rules/AD5002.DoNotAllowExecutableStack.md) | Security | ✓ | ✓ | ✓ |
| AD5003 | [EnableStackProtectorMachO](docs/rules/AD5003.EnableStackProtectorMachO.md) | Security | ✓ | ✗ | ✓ |
| AD5004 | [UseFortifiedFunctionsMachO](docs/rules/AD5004.UseFortifiedFunctionsMachO.md) | Security | ✓ | ✗ | ✗ |
| AD5005 | [DoNotAllowExecutableHeap](docs/rules/AD5005.DoNotAllowExecutableHeap.md) | Security | ✓ | ✓ | ✓ |
| AD5006 | [UseTwoLevelNamespace](docs/rules/AD5006.UseTwoLevelNamespace.md) | Security | ✓ | ✓ | ✓ |
| AD5007 | [EnableArmPACMachO](docs/rules/AD5007.EnableArmPACMachO.md) | Security | ✓ | ✓ | ✓ |
| AD5008 | [EnableClangSafeStackMachO](docs/rules/AD5008.EnableClangSafeStackMachO.md) | Security | ✓ | ✗ | ✗ |
| AD5009 | [DoNotUseWeakDylib](docs/rules/AD5009.DoNotUseWeakDylib.md) | Security | ✓ | ✓ | ✓ |
| AD5010 | [EnableAutomaticReferenceCounting](docs/rules/AD5010.EnableAutomaticReferenceCounting.md) | Security | ✓ | ✗ | ✗ |
| AD5011 | [RequireCodeSignature](docs/rules/AD5011.RequireCodeSignature.md) | Security | ✓ | ✓ | ✓ |
| AD5012 | [ValidateSegmentPermissions](docs/rules/AD5012.ValidateSegmentPermissions.md) | Security | ✓ | ✓ | ✓ |
| AD5013 | [DoNotUseBannedApis](docs/rules/AD5013.DoNotUseBannedApis.md) | Security | ✓ | ✗ | ✓ |
| AD5014 | [UseAddressSanitizer](docs/rules/AD5014.UseAddressSanitizer.md) | Security | ✓ | ✗ | ✓ |
| AD5015 | [DoNotStaticallyLinkOpenSSL](docs/rules/AD5015.DoNotStaticallyLinkOpenSSL.md) | Security | ✓ | ✓ | ✓ |
| AD5016 | [NoUnicodeSymbolsMachO](docs/rules/AD5016.NoUnicodeSymbolsMachO.md) | Security | ✓ | ✓ | ✓ |
| AD5017 | [EnableLTOMachO](docs/rules/AD5017.EnableLTOMachO.md) | Performance | ✓ | ✓ | ✓ |
| AD5018 | [RequireMinimumOSVersion](docs/rules/AD5018.RequireMinimumOSVersion.md) | Security | ✓ | ✓ | ✓ |
| AD5019 | [UseRestrictSegment](docs/rules/AD5019.UseRestrictSegment.md) | Security | ✓ | ✓ | ✓ |
| AD5020 | [RustEnableSanitizersMachO](docs/rules/AD5020.RustEnableSanitizersMachO.md) | Security | ✗ | ✓ | ✗ |
| AD5021 | [RustEnableSecureSourceHashMachO](docs/rules/AD5021.RustEnableSecureSourceHashMachO.md) | Security | ✗ | ✓ | ✗ |
| AD5022 | [RustMachOEnableLTO](docs/rules/AD5022.RustMachOEnableLTO.md) | Performance | ✗ | ✓ | ✗ |
| AD5023 | [EnableUBSanMachO](docs/rules/AD5023.EnableUBSanMachO.md) | Security | ✓ | ✗ | ✗ |
| AD5024 | [EnableStackClashProtectionMachO](docs/rules/AD5024.EnableStackClashProtectionMachO.md) | Security | ✓ | ✗ | ✗ |
| AD5025 | [EnableControlFlowIntegrityMachO](docs/rules/AD5025.EnableControlFlowIntegrityMachO.md) | Security | ✓ | ✗ | ✗ |
| AD5026 | [EnableArmBTIMachO](docs/rules/AD5026.EnableArmBTIMachO.md) | Security | ✓ | ✓ | ✓ |
| AD5027 | [EnableSpeculativeLoadHardeningMachO](docs/rules/AD5027.EnableSpeculativeLoadHardeningMachO.md) | Security | ✓ | ✗ | ✗ |
| AD5028 | [EnableOptimizationMachO](docs/rules/AD5028.EnableOptimizationMachO.md) | Performance | ✓ | ✓ | ✓ |
| AD5029 | [EnableArmMTEMachO](docs/rules/AD5029.EnableArmMTEMachO.md) | Security | ✓ | ✗ | ✗ |
| AD5030 | [EnableExceptionHandlingMachO](docs/rules/AD5030.EnableExceptionHandlingMachO.md) | Security | ✓ | ✓ | ✓ |
| AD5031 | [CheckNotEncrypted](docs/rules/AD5031.CheckNotEncrypted.md) | Security | ✓ | ✓ | ✓ |
| AD5040 | [DoNotUseUncheckedOptimization](docs/rules/AD5040.DoNotUseUncheckedOptimization.md) | Security | ✓ | ✓ | ✓ |
| AD5060 | [DetectPackedBinary](docs/rules/AD5060.DetectPackedBinary.md) | Security | ✓ | ✓ | ✓ |

## Output Formats

Aldur supports multiple output formats via the `--format` option:

| Format | Option | Description |
|--------|--------|-------------|
| SARIF | `--format sarif` | Structured JSON for tooling integration (default) |
| Text | `--format text` | Plain text for terminals without color support |
| Text (color) | `--format text-color` | ANSI-colored text for terminal display |
| GitHub Actions| | `--format gha` | GitHub Action warning compatible output |

### SARIF Output

[SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) (Static Analysis Results Interchange Format) is the default output format, supported by:

- GitHub Code Scanning
- Azure DevOps
- Visual Studio
- VS Code (with SARIF Viewer extension)
- Many other security tools

```bash
# Output to SARIF file
aldur analyze -o results.sarif /path/to/binary

# Explicitly specify SARIF format
aldur analyze --format sarif -o results.json /path/to/binary
```

### Text Output

Human-readable text output for terminal display or log files:

```bash
# Plain text (no colors)
aldur analyze --format text /path/to/binary

# Colored text for terminal
aldur analyze --format text-color /path/to/binary

# Show passing rules too
aldur analyze --format text --show-passed /path/to/binary
```

Example text output:

```
/usr/bin/ls
  ✓ AD3001  EnablePositionIndependentExecutable  PASS
  ✓ AD3002  DoNotMarkStackAsExecutable           PASS
  ✓ AD3010  EnableReadOnlyRelocations            PASS
  ✗ AD3011  EnableBindNow                        FAIL
            Does not enable BIND_NOW. Link with -Wl,-z,now.
  ✓ AD3014  NoTextRelocations                    PASS
```

### SARIF Example

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "aldur",
        "version": "0.1.0",
        "rules": [...]
      }
    },
    "results": [
      {
        "ruleId": "AD3001",
        "level": "none",
        "kind": "pass",
        "message": {
          "text": "'/usr/bin/ls' is a position independent executable."
        }
      },
      {
        "ruleId": "AD3011",
        "level": "error",
        "kind": "fail",
        "message": {
          "text": "'/usr/bin/ls' does not enable BIND_NOW. Consider linking with -Wl,-z,now."
        }
      }
    ]
  }]
}
```

### Azure DevOps

```yaml
- script: |
    aldur analyze -o $(Build.ArtifactStagingDirectory)/binskim.sarif $(Build.BinariesDirectory)
  displayName: 'Run Binary Security Analysis'

- task: PublishBuildArtifacts@1
  inputs:
    pathtoPublish: '$(Build.ArtifactStagingDirectory)/binskim.sarif'
    artifactName: 'SecurityResults'
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
## Security

For information about reporting security vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Microsoft BinSkim](https://github.com/microsoft/BinSkim) - The original .NET implementation that inspired Aldur
- The Rust security community for excellent parsing libraries

## Related Projects

- [checksec.sh](https://github.com/slimm609/checksec.sh) - Shell script for checking binary security properties
- [checksec.rs](https://github.com/etke/checksec.rs) - Rust implementation of checksec
- [annobin](https://sourceware.org/annobin/) - Binary annotation and hardening checker for Red Hat/Fedora
- [LIEF](https://github.com/lief-project/LIEF) - Library for binary instrumentation
- [radare2](https://github.com/radareorg/radare2) - Reverse engineering framework
