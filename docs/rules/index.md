# Security Rules Overview

Aldur includes 125+ security rules covering compiler flags, memory protections, and exploit mitigations across PE (Windows), ELF (Linux/Unix), and Mach-O (macOS) binaries.

## Rule Categories

| Prefix | Platform | Description |
|--------|----------|-------------|
| AD2xxx | PE (Windows) | Windows binary security checks |
| AD3xxx | ELF (Linux) | Linux/Unix binary security checks |
| AD4xxx | Reporting | Informational/reporting rules |
| AD5xxx | Mach-O (macOS) | macOS binary security checks |
| AD6xxx | Optimization | Build optimization checks |

## Rule Severity Levels

| Level | Description |
|-------|-------------|
| **Error** | Critical security issue that should be fixed |
| **Warning** | Important security recommendation |
| **Note** | Informational or optional enhancement |

## Quick Reference

### Essential Security Features

| Feature | PE | ELF | Mach-O |
|---------|-----|-----|--------|
| ASLR/PIE | AD2009 | AD3001 | AD5001 |
| DEP/NX | AD2016 | AD3002, AD3006 | AD5002 |
| Stack Canaries | AD2011 | AD3003 | AD5003 |
| CFG/CFI | AD2008 | AD3015, AD3036 | AD5025 |
| RELRO | - | AD3010 | - |
| Stack Clash | AD2037 | AD3005 | AD5024 |

### Compiler Requirements

| Feature | PE (MSVC) | ELF (GCC/Clang) | Mach-O (Clang) |
|---------|-----------|-----------------|----------------|
| Stack Protection | /GS | -fstack-protector-strong | -fstack-protector-strong |
| Control Flow | /guard:cf | -fcf-protection | -mbranch-protection |
| Fortify | - | -D_FORTIFY_SOURCE=2 | -D_FORTIFY_SOURCE=2 |
| SDL Checks | /sdl | - | - |

## Detailed Rule Documentation

Each rule has detailed documentation including:

- **Description**: What the rule checks
- **Why It Matters**: Security implications
- **Performance Considerations**: Runtime overhead
- **Resolution**: How to fix the issue
- **References**: External documentation

Browse rules by platform:

- [PE (Windows) Rules](pe.md) - AD2xxx series
- [ELF (Linux) Rules](elf.md) - AD3xxx series
- [Mach-O (macOS) Rules](macho.md) - AD5xxx series

## Rule Tags

Rules are tagged for profile filtering:

| Tag | Description |
|-----|-------------|
| `critical` | Essential security checks |
| `recommended` | Recommended hardening |
| `hardening` | Advanced hardening features |
| `memory-safety` | Memory protection features |
| `control-flow` | Control flow integrity |
| `intel-only` | Intel-specific features |
| `arm-only` | ARM-specific features |
| `rust` | Rust-specific checks |
| `debug-only` | Development/testing only |
| `optimization` | Performance optimizations |
