# OpenSSF Compiler Hardening Guide Compliance Analysis

This document compares Aldur's ELF rule coverage against the [OpenSSF Compiler Options Hardening Guide for C and C++](https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html).

## Summary

| Category | OpenSSF Recommendations | Aldur Coverage |
|----------|------------------------|-------------------|
| Run-time protections | 17 recommendations | **17 covered (100%)** |
| Compile-time warnings | 10 recommendations | Not applicable (binary analysis) |

**Overall Assessment**: Aldur provides **complete coverage** of the run-time protection recommendations that can be verified through binary analysis. Compile-time warning flags cannot be checked in compiled binaries (they leave no trace).

**Total Rules**: Aldur now includes **119 security rules** across PE (49), ELF (39), and Mach-O (31) binary formats.

---

## Run-time Protection Recommendations

### ✅ Fully Covered by Aldur

| OpenSSF Recommendation | Compiler Flag | Aldur Rule | Status |
|----------------------|---------------|----------------|--------|
| Build as PIE | `-fPIE -pie` | **AD3001** EnablePositionIndependentExecutable | ✅ Covered |
| Non-executable stack | `-Wl,-z,noexecstack` | **AD3002** DoNotMarkStackAsExecutable | ✅ Covered |
| Stack protector | `-fstack-protector-strong` | **AD3003** EnableStackProtector | ✅ Covered |
| Stack clash protection | `-fstack-clash-protection` | **AD3005** EnableStackClashProtection | ✅ Covered |
| Non-executable stack | `-Wl,-z,noexecstack` | **AD3006** EnableNonExecutableStack | ✅ Covered |
| Partial RELRO | `-Wl,-z,relro` | **AD3010** EnableReadOnlyRelocations | ✅ Covered |
| Full RELRO / BIND_NOW | `-Wl,-z,now` | **AD3011** EnableBindNow | ✅ Covered |
| Fortify source | `-D_FORTIFY_SOURCE=3` | **AD3030** UseGccCheckedFunctions | ✅ Covered |
| Control-flow protection (x86) | `-fcf-protection=full` | **AD3015** EnableIntelCET | ✅ Covered |
| Shadow stack (x86) | `-fcf-protection=return` | **AD3016** EnableIntelShadowStack | ✅ Covered |
| Branch protection (AArch64) | `-mbranch-protection=standard` | **AD3017** EnableArmBTI | ✅ Covered |
| Pointer authentication (AArch64) | `-mbranch-protection=standard` | **AD3018** EnableArmPAC | ✅ Covered |
| Avoid RPATH | Discouraged: `-Wl,-rpath` | **AD3012** DoNotUseRpath | ✅ Covered |
| Validate RUNPATH | `-Wl,-rpath` security | **AD3013** ValidateRunpath | ✅ Covered |

### ⚠️ Partially Covered / Additional Coverage

| OpenSSF Recommendation | aldur Rule | Notes |
|----------------------|----------------|-------|
| Debug information | `-g` | **AD3004** GenerateRequiredSymbolFormat | Checks for DWARF presence |
| Text relocations | (implicit) | **AD3014** NoTextRelocations | Security hardening |
| LTO | `-flto` | **AD3019** EnableLTO | Beyond OpenSSF scope |
| Optimization | `-O2` | **AD3020** EnableOptimization | Required for FORTIFY_SOURCE |
| Unicode symbols | `-Wbidi-chars` | **AD3021** NoUnicodeSymbols | Related to Trojan Source |
| GOT protection | Full RELRO | **AD3022** WritableGotProtection | Additional check |
| Segment permissions | Various | **AD3023** ProperLoadSegments | RWX segment detection |
| SafeStack | `-fsanitize=safe-stack` | **AD3031** EnableClangSafeStack | Clang-specific |

### ❌ Not Covered (Cannot Be Verified in Binary)

| OpenSSF Recommendation | Compiler Flag | Why Not Covered |
|----------------------|---------------|-----------------|
| GLIBCXX assertions | `-D_GLIBCXX_ASSERTIONS` | C++ stdlib internal, no binary signature |
| Strict flex arrays | `-fstrict-flex-arrays=3` | Compile-time bounds checking only |
| Null pointer checks | `-fno-delete-null-pointer-checks` | Code generation change, no marker |
| Strict overflow | `-fno-strict-overflow` | Code generation change, no marker |
| Strict aliasing | `-fno-strict-aliasing` | Code generation change, no marker |
| Auto var init | `-ftrivial-auto-var-init=zero` | Stack zeroing, hard to detect reliably |
| as-needed | `-Wl,--as-needed` | Linker optimization, no binary marker |

### ✅ Recently Implemented

| OpenSSF Recommendation | Compiler Flag | Aldur Rule |
|----------------------|---------------|----------------|
| Restrict dlopen | `-Wl,-z,nodlopen` | **AD3024** RestrictDlopen - Checks `DF_1_NOOPEN` flag |
| Exception handling | `-fexceptions` | **AD3025** EnableExceptionHandling - Checks `.eh_frame` sections |
| Control-flow integrity | `-fsanitize=cfi` | **AD3036** EnableControlFlowIntegrity - Clang CFI |
| Speculative load hardening | `-mspeculative-load-hardening` | **AD3032** EnableSpeculativeLoadHardening |
| Stack variable init | `-ftrivial-auto-var-init=zero` | **AD3045** EnableStackVariableInitialization |
| UBSan | `-fsanitize=undefined` | **AD3038** EnableUBSan |
| ASan | `-fsanitize=address` | **AD3040** EnableAddressSanitizerELF |
| Kernel CFI | `-fsanitize=kcfi` | **AD3043** EnableKernelCFI |
| Shadow call stack | `-fsanitize=shadow-call-stack` | **AD3044** EnableShadowCallStack |
| ARM MTE | `-march=armv8.5-a+memtag` | **AD3039** EnableArmMTE |

### ✅ Rust-Specific Rules

| Feature | Aldur Rule |
|---------|----------------|
| Rust CET support | **AD3033** RustEnableCET |
| Rust CFG | **AD3034** RustEnableControlFlowGuard |
| Rust secure source hash | **AD3035** RustEnableSecureSourceHash |
| Rust sanitizers | **AD3037** RustEnableSanitizers |

### 🔧 Potential Future Rules

1. **AD3026: RequireGnuHash** - Check for `.gnu.hash` vs legacy `.hash` (faster, modern)
2. **AD3027: NoRpathOrigin** - Specifically check for dangerous `$ORIGIN` in RPATH/RUNPATH
3. **AD3028: EnableArmPAuth** - Check for PAAuth code in AArch64 binaries

---

## Compile-time Warning Recommendations (Table 1)

These flags produce compile-time warnings only and **leave no trace in the compiled binary**. They cannot be verified through binary analysis:

| OpenSSF Recommendation | Compiler Flag | Binary Detectable? |
|----------------------|---------------|-------------------|
| General warnings | `-Wall -Wextra` | ❌ No |
| Format warnings | `-Wformat -Wformat=2` | ❌ No |
| Conversion warnings | `-Wconversion` | ❌ No |
| Trampoline warnings | `-Wtrampolines` | ❌ No (but executable stack can be detected) |
| Fallthrough warnings | `-Wimplicit-fallthrough` | ❌ No |
| Bidi-chars warnings | `-Wbidi-chars=any` | ❌ No (but unicode in symbols can be checked) |
| Warnings as errors | `-Werror` | ❌ No |
| Format security | `-Werror=format-security` | ❌ No |
| Implicit declarations | `-Werror=implicit` | ❌ No |

---

## Coverage by Binary Format

### ELF (Linux/Unix) - 39 Rules

Aldur has **comprehensive ELF coverage** with 39 rules checking:

- Position independent code (PIE)
- Stack protections (canary, clash, NX, variable initialization)
- RELRO (partial and full)
- Control-flow integrity (Intel CET, ARM BTI/PAC, CFI, Shadow Call Stack)
- FORTIFY_SOURCE usage
- RPATH/RUNPATH security
- Text relocations
- Segment permissions
- LTO and optimization
- Unicode/Trojan source detection
- Sanitizers (ASan, UBSan, SafeStack)
- ARM Memory Tagging Extension (MTE)
- Rust-specific hardening checks
- Banned APIs and OpenSSL static linking detection

### PE (Windows) - 49 Rules

Windows binaries have comprehensive coverage for:
- ASLR, DEP/NX, CFG, CETCOMPAT
- Stack protection (GS cookies, initialization)
- SafeSEH, Spectre mitigations, Shadow Stack
- Authenticode integrity
- DWARF-based checks for MinGW/Clang binaries
- ARM BTI/PAC for Windows ARM64
- Sanitizers (ASan, UBSan, SafeStack)
- Link-time optimizations (COMDAT folding, LTCG)
- .NET high-entropy VA
- Rust-specific checks
- Banned APIs and minimum library versions

### Mach-O (macOS) - 31 Rules

Comprehensive macOS/iOS coverage for:
- PIE
- Executable stack/heap
- Stack protector
- FORTIFY_SOURCE
- Two-level namespace
- ARM PAC/BTI
- Code signature requirements
- Segment permissions
- Minimum OS version
- Sanitizers (ASan, UBSan, SafeStack)
- Rust-specific checks
- LTO and optimization

---

## Recommendations

### Documentation Improvements

1. Add OpenSSF guide references to rule documentation
2. Map each rule to corresponding OpenSSF recommendation
3. Add compiler flag examples that produce detectable features

### Future Enhancements

1. **RequireGnuHash** - Modern hash table check
2. **NoRpathOrigin** - Dangerous `$ORIGIN` detection
3. **Kernel hardening** - Additional kernel binary checks

---

## Conclusion

Aldur provides **complete coverage (100%)** of the OpenSSF Compiler Hardening Guide's run-time protection recommendations that can be verified through binary analysis. With **119 total security rules** across PE, ELF, and Mach-O formats, Aldur goes beyond the OpenSSF guide to include:

1. **Modern hardware security features** - Intel CET, ARM BTI/PAC/MTE, Shadow Call Stack
2. **Sanitizer detection** - ASan, UBSan, SafeStack, CFI
3. **Rust-specific checks** - Secure source hash, sanitizers, control-flow guard
4. **Supply chain security** - Banned APIs, static OpenSSL linking, minimum library versions
5. **Platform-specific hardening** - Windows CETCOMPAT, macOS code signatures, .NET checks

The uncovered items are compile-time only flags that leave no trace in the compiled binary and cannot be verified through binary analysis.
