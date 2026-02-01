# ELF (Linux/Unix) Security Rules

Rules for analyzing ELF (Executable and Linkable Format) binaries on Linux and Unix systems.

## Memory Protection

| Rule | Name | Severity | Description |
|------|------|----------|-------------|
| [AD3001](../AD3001.EnablePositionIndependentExecutable.md) | EnablePositionIndependentExecutable | Error | Enable PIE for ASLR |
| [AD3002](../AD3002.DoNotMarkStackAsExecutable.md) | DoNotMarkStackAsExecutable | Error | Non-executable stack |
| [AD3006](../AD3006.EnableNonExecutableStack.md) | EnableNonExecutableStack | Error | Verify NX stack |
| [AD3010](../AD3010.EnableReadOnlyRelocations.md) | EnableReadOnlyRelocations | Warning | Enable RELRO |
| [AD3011](../AD3011.EnableBindNow.md) | EnableBindNow | Warning | Enable BIND_NOW |
| [AD3014](../AD3014.NoTextRelocations.md) | NoTextRelocations | Error | No text relocations |
| [AD3022](../AD3022.WritableGotProtection.md) | WritableGotProtection | Warning | GOT protection |

## Stack Protection

| Rule | Name | Severity | Description |
|------|------|----------|-------------|
| [AD3003](../AD3003.EnableStackProtector.md) | EnableStackProtector | Error | Enable stack canaries |
| [AD3005](../AD3005.EnableStackClashProtection.md) | EnableStackClashProtection | Warning | Stack clash protection |
| [AD3030](../AD3030.UseGccCheckedFunctions.md) | UseGccCheckedFunctions | Warning | Use FORTIFY_SOURCE |
| [AD3045](../AD3045.EnableStackVariableInitialization.md) | EnableStackVariableInitialization | Warning | Auto-init stack vars |
| [AD3051](../AD3051.CheckFortifySourceLevel.md) | CheckFortifySourceLevel | Warning | Check FORTIFY level |

## Control Flow (Intel x86_64)

| Rule | Name | Severity | Description |
|------|------|----------|-------------|
| [AD3015](../AD3015.EnableIntelCET.md) | EnableIntelCET | Warning | Enable Intel CET/IBT |
| [AD3016](../AD3016.EnableIntelShadowStack.md) | EnableIntelShadowStack | Warning | Enable Shadow Stack |
| [AD3036](../AD3036.EnableControlFlowIntegrity.md) | EnableControlFlowIntegrity | Warning | Enable Clang CFI |

## Control Flow (ARM64)

| Rule | Name | Severity | Description |
|------|------|----------|-------------|
| [AD3017](../AD3017.EnableArmBTI.md) | EnableArmBTI | Warning | ARM Branch Target Identification |
| [AD3018](../AD3018.EnableArmPAC.md) | EnableArmPAC | Warning | ARM Pointer Authentication |
| [AD3039](../AD3039.EnableArmMTE.md) | EnableArmMTE | Warning | ARM Memory Tagging Extension |
| [AD3044](../AD3044.EnableShadowCallStack.md) | EnableShadowCallStack | Note | Shadow Call Stack |

## Library Path Security

| Rule | Name | Severity | Description |
|------|------|----------|-------------|
| [AD3012](../AD3012.DoNotUseRpath.md) | DoNotUseRpath | Warning | Don't use deprecated RPATH |
| [AD3013](../AD3013.ValidateRunpath.md) | ValidateRunpath | Warning | Validate RUNPATH entries |
| [AD3024](../AD3024.RestrictDlopen.md) | RestrictDlopen | Warning | Restrict dlopen usage |

## Compiler & Linker

| Rule | Name | Severity | Description |
|------|------|----------|-------------|
| [AD3004](../AD3004.GenerateRequiredSymbolFormat.md) | GenerateRequiredSymbolFormat | Note | Required symbol format |
| [AD3019](../AD3019.EnableLTO.md) | EnableLTO | Note | Enable Link-Time Optimization |
| [AD3020](../AD3020.EnableOptimization.md) | EnableOptimization | Note | Enable optimization |
| [AD3025](../AD3025.EnableExceptionHandling.md) | EnableExceptionHandling | Warning | Exception handling frames |
| [AD3050](../AD3050.EnableGccDefs.md) | EnableGccDefs | Note | GCC hardening defines |

## Clang-Specific

| Rule | Name | Severity | Description |
|------|------|----------|-------------|
| [AD3031](../AD3031.EnableClangSafeStack.md) | EnableClangSafeStack | Warning | Enable SafeStack |
| [AD3032](../AD3032.EnableSpeculativeLoadHardening.md) | EnableSpeculativeLoadHardening | Warning | Speculative load hardening |

## Rust-Specific

| Rule | Name | Severity | Description |
|------|------|----------|-------------|
| [AD3033](../AD3033.RustEnableCET.md) | RustEnableCET | Warning | Rust CET support |
| [AD3034](../AD3034.RustEnableControlFlowGuard.md) | RustEnableControlFlowGuard | Warning | Rust CFG |
| [AD3035](../AD3035.RustEnableSecureSourceHash.md) | RustEnableSecureSourceHash | Note | Secure source hashing |
| [AD3037](../AD3037.RustEnableSanitizers.md) | RustEnableSanitizers | Note | Rust sanitizers |

## Sanitizers (Development)

| Rule | Name | Severity | Description |
|------|------|----------|-------------|
| [AD3038](../AD3038.EnableUBSan.md) | EnableUBSan | Note | UndefinedBehaviorSanitizer |
| [AD3040](../AD3040.EnableAddressSanitizerELF.md) | EnableAddressSanitizerELF | Note | AddressSanitizer |

## Supply Chain

| Rule | Name | Severity | Description |
|------|------|----------|-------------|
| [AD3021](../AD3021.NoUnicodeSymbols.md) | NoUnicodeSymbols | Warning | No Unicode in symbols |
| [AD3041](../AD3041.DoNotUseBannedApisELF.md) | DoNotUseBannedApisELF | Warning | Banned API usage |
| [AD3042](../AD3042.DoNotStaticallyLinkOpenSSLELF.md) | DoNotStaticallyLinkOpenSSLELF | Warning | Don't statically link OpenSSL |
