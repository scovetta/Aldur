# Security Profiles

Profiles provide predefined configurations for different security requirements. Rules are tagged with semantic labels, and profiles filter rules based on these tags.

## Available Profiles

| Profile | Description | Use Case |
|---------|-------------|----------|
| `default` | Critical and recommended security checks | General-purpose scanning |
| `strict` | All security rules elevated to error | High-security environments |
| `relaxed` | Only critical security checks | Legacy/compatibility scanning |
| `openssf` | OpenSSF Compiler Hardening Guide compliance | Standards compliance |
| `android` | Android CDD requirements | Android app/library development |
| `rhel` | Red Hat annocheck-compatible | RHEL/Fedora package builds |
| `fips` | FIPS 140-2/3 compliance focus | Government/regulated environments |
| `nightly` | All checks including Rust nightly requirements | Rust nightly development |
| `optimization` | Performance and binary size checks | Build optimization validation |

## Using Profiles

```bash
# Use default profile (implicit)
aldur analyze ./build/

# Use strict profile for CI/CD
aldur analyze --profile strict ./build/

# Use OpenSSF profile for compliance checking
aldur analyze --profile openssf ./build/

# Use Android profile for mobile libraries
aldur analyze --profile android ./libs/

# List available profiles
aldur list-profiles
```

## Profile Details

### default

The `default` profile focuses on essential security checks. It excludes:

- **Hardening rules** (Spectre mitigations, SafeStack, CFI) — use `strict` for these
- **Debug-only rules** (ASan, UBSan) — these check for sanitizer presence
- **Optimization rules** (LTCG, COMDAT folding) — use `optimization` for these
- **Nightly rules** — require Rust nightly compiler

### strict

All security rules are enabled and elevated to error severity. Use this for:

- CI/CD pipelines with strict security requirements
- High-security environments
- Pre-release security validation

### openssf

Enforces the [OpenSSF Compiler Options Hardening Guide](https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html):

- Position Independent Executable (PIE)
- Non-executable stack
- Stack protector (canary)
- Stack clash protection
- Full RELRO with immediate binding
- Control-flow protection (CET on Intel, BTI/PAC on ARM)
- FORTIFY_SOURCE usage
- Exception handling frames

## Rule Inclusion/Exclusion

Override any profile by including or excluding specific rules:

```bash
# Add specific rules to a profile
aldur analyze --profile relaxed --include AD3033,AD3035 ./build/

# Exclude rules from a profile
aldur analyze --profile strict --exclude AD2041,AD2045 ./build/

# Combine both
aldur analyze --profile default --include AD3033 --exclude AD2024 ./build/
```

## Custom Profiles

Define custom profiles in a file for advanced use cases.

### Custom Profile File Format

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

[legacy_compat]
# Start with relaxed profile
profile:relaxed
# Remove specific rules
-AD3010
-AD3011
```

### Using Custom Profiles

```bash
aldur analyze --custom-profiles ./my-profiles.ini --profile minimal ./build/
```
