# Quick Start

This guide walks you through analyzing your first binary with Aldur.

## Basic Usage

### Analyze a Single Binary

```bash
aldur analyze /path/to/binary
```

Example output:
```
/path/to/binary
  ✗ AD3001 (error): Binary is not a Position Independent Executable (PIE)
  ✗ AD3003 (error): Binary does not enable stack protector
  ✓ AD3002 (pass): Binary has non-executable stack
  ✓ AD3010 (pass): Binary has RELRO enabled
```

### Analyze a Directory

```bash
# Analyze all binaries in a directory
aldur analyze /path/to/binaries/

# Analyze recursively
aldur analyze -r /path/to/binaries/
```

### Analyze Archives

Aldur can scan binaries inside archives (APK, IPA, ZIP, TAR, etc.):

```bash
# Analyze an Android APK
aldur analyze app.apk

# Analyze an iOS IPA
aldur analyze app.ipa

# Analyze a Windows MSIX
aldur analyze package.msix
```

## Output Formats

### Text Output (Default)

```bash
aldur analyze binary
```

### SARIF Output (for CI/CD)

```bash
aldur analyze -o results.sarif binary
```

### Show Passing Rules

```bash
aldur analyze --show-passed binary
```

## Using Security Profiles

Profiles provide pre-configured rule sets for different security requirements:

```bash
# Default profile (essential security checks)
aldur analyze binary

# Strict profile (all rules as errors)
aldur analyze --profile strict binary

# OpenSSF compliance profile
aldur analyze --profile openssf binary

# Android profile
aldur analyze --profile android app.apk
```

Available profiles:

| Profile | Description |
|---------|-------------|
| `default` | Essential security checks |
| `strict` | All rules elevated to error |
| `relaxed` | Only critical checks |
| `openssf` | OpenSSF Compiler Hardening Guide |
| `android` | Android CDD requirements |
| `rhel` | Red Hat annocheck compatible |

## Common Workflows

### CI/CD Integration

```bash
# Generate SARIF for GitHub Code Scanning
aldur analyze -o security.sarif --format sarif ./build/

# Fail if any errors found
aldur analyze --level error ./build/ || exit 1
```

### Security Audit

```bash
# Full audit with all checks and statistics
aldur analyze -r --profile strict --show-passed --statistics /path/to/binaries/
```

### Compare Against Baseline

```bash
# Save current results as baseline
aldur analyze --save-baseline baseline.sarif ./build/

# Later, compare new build against baseline
aldur analyze --baseline baseline.sarif ./build/
```

## Next Steps

- [Command Reference](../guide/commands.md) - Full command documentation
- [Security Profiles](../guide/profiles.md) - Profile details
- [GitHub Action](github-action.md) - CI/CD integration
