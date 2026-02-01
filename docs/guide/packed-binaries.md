# Packed Binary Detection

## Overview

Aldur can detect when a binary has been compressed or packed using executable packers like UPX, ASPack, Themida, VMProtect, and others. When a packer is detected, Aldur will emit a warning because packed binaries strip or encrypt metadata that security analysis tools rely on, making analysis results potentially unreliable.

## Why Packed Binaries Are Problematic

Executable packers work by:

1. Compressing or encrypting the original binary
2. Stripping section headers, debug information, and symbol tables
3. Adding a small unpacker stub that decompresses the binary at runtime

This means that when Aldur analyzes a packed binary:

- **Section information is missing or incorrect** - Rules that check section permissions may fail or give wrong results
- **Debug symbols are stripped** - Compiler detection and DWARF-based rules cannot work
- **Import tables are hidden** - API usage checks may miss vulnerabilities
- **Security flags may be from the packer, not the original binary** - Results may reflect the packer's properties, not your code

## Detected Packers

Aldur can detect the following packers:

| Packer | Platform | Detection Method |
|--------|----------|------------------|
| UPX | PE, ELF, Mach-O | `UPX!` magic, section names (`UPX0`, `UPX1`) |
| ASPack | PE | `.aspack`, `.adata` sections |
| PECompact | PE | `PEC2` signature, `.pec1`, `.pec2` sections |
| Themida/WinLicense | PE | `.themida` section, string signatures |
| VMProtect | PE | `.vmp0`, `.vmp1` sections, string signatures |
| Enigma Protector | PE | `.enigma` section, string signatures |
| MPRESS | PE | `.MPRESS1`, `.MPRESS2` sections |
| Petite | PE | `.petite` section |
| FSG | PE | `FSG!` section |
| NSPack | PE | `.nsp0`, `.nsp1` sections |
| kkrunchy | PE, ELF | String signature |
| .NET Reactor | PE (.NET) | String signature |
| ConfuserEx | PE (.NET) | String signature |

## Unpacking Binaries

To get accurate security analysis results, you should unpack the binary before scanning. Here are instructions for common packers:

### UPX

UPX is open-source and includes a built-in decompression option:

```bash
# Download UPX from https://upx.github.io/

# Decompress a UPX-packed binary
upx -d packed_binary

# Decompress to a new file (keeps original)
upx -d -o unpacked_binary packed_binary

# Force decompression even if file seems corrupted
upx -d -f packed_binary
```

### ASPack

ASPack does not include an official unpacker. Options include:

- **AspackDie** - Third-party unpacker (Windows)
- **Manual unpacking** - Using a debugger like x64dbg or OllyDbg

### PECompact

- **unpecompact** - Third-party unpacker
- **Manual unpacking** - Using dynamic analysis

### Themida/VMProtect

These are commercial protectors designed to resist unpacking:

- No automated unpacker available
- Requires advanced reverse engineering skills
- Consider requesting an unprotected build from the vendor

### .NET Packers

For .NET-specific packers like ConfuserEx or .NET Reactor:

- **de4dot** - Open-source .NET deobfuscator
- **dnSpy** - .NET debugger and assembly editor

```bash
# Using de4dot
de4dot protected_assembly.dll -o unpacked_assembly.dll
```

## Best Practices

1. **Request unprotected builds for security audits** - If you're auditing third-party software, ask the vendor for an unprotected build specifically for security analysis

2. **Scan before packing** - Run Aldur on your binaries before applying any packer to get accurate results

3. **Document packing decisions** - If you choose to pack binaries, document which packer you use and why

4. **Consider alternatives** - Instead of packing for size, consider:
   - Link-time optimization (LTO)
   - Dead code elimination
   - Compression at the installer/distribution level

## Disabling the Warning

If you want to suppress the packed binary warning, you can exclude the rule:

```bash
# Exclude the packer detection rule
aldur analyze --exclude-rules AD2060,AD3060,AD5060 ./binary

# Or in your aldur.toml configuration
[analysis]
exclude_rules = ["AD2060", "AD3060", "AD5060"]
```

However, be aware that other analysis results may still be unreliable.

## Rule Reference

| Rule ID | Format | Description |
|---------|--------|-------------|
| AD2060 | PE | DetectPackedBinary - Detect packed Windows binaries |
| AD3060 | ELF | DetectPackedBinary - Detect packed Linux binaries |
| AD5060 | Mach-O | DetectPackedBinary - Detect packed macOS binaries |
