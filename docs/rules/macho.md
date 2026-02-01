# Mach-O (macOS/iOS) Security Rules

Rules for analyzing Mach-O binaries on macOS and iOS.

## Memory Protection

| Rule | Name | Severity | Description |
|------|------|----------|-------------|
| [AD5001](../AD5001.EnablePositionIndependentExecutableMachO.md) | EnablePositionIndependentExecutableMachO | Error | Enable PIE for ASLR |
| [AD5002](../AD5002.DoNotAllowExecutableStack.md) | DoNotAllowExecutableStack | Error | Non-executable stack |
| [AD5005](../AD5005.DoNotAllowExecutableHeap.md) | DoNotAllowExecutableHeap | Warning | Non-executable heap |
| [AD5012](../AD5012.ValidateSegmentPermissions.md) | ValidateSegmentPermissions | Warning | Validate segment permissions |

## Stack Protection

| Rule | Name | Severity | Description |
|------|------|----------|-------------|
| [AD5003](../AD5003.EnableStackProtectorMachO.md) | EnableStackProtectorMachO | Error | Enable stack canaries |
| [AD5004](../AD5004.UseFortifiedFunctionsMachO.md) | UseFortifiedFunctionsMachO | Warning | Use FORTIFY_SOURCE |
| [AD5024](../AD5024.EnableStackClashProtectionMachO.md) | EnableStackClashProtectionMachO | Warning | Stack clash protection |

## Control Flow (ARM64)

| Rule | Name | Severity | Description |
|------|------|----------|-------------|
| [AD5007](../AD5007.EnableArmPACMachO.md) | EnableArmPACMachO | Warning | ARM Pointer Authentication |
| [AD5025](../AD5025.EnableControlFlowIntegrityMachO.md) | EnableControlFlowIntegrityMachO | Warning | Clang CFI |
| [AD5026](../AD5026.EnableArmBTIMachO.md) | EnableArmBTIMachO | Warning | ARM Branch Target Identification |
| [AD5029](../AD5029.EnableArmMTEMachO.md) | EnableArmMTEMachO | Warning | ARM Memory Tagging Extension |

## Code Signing

| Rule | Name | Severity | Description |
|------|------|----------|-------------|
| [AD5011](../AD5011.RequireCodeSignature.md) | RequireCodeSignature | Warning | Require code signature |
| [AD5031](../AD5031.CheckNotEncrypted.md) | CheckNotEncrypted | Note | Check encryption status |

## Linker Settings

| Rule | Name | Severity | Description |
|------|------|----------|-------------|
| [AD5006](../AD5006.UseTwoLevelNamespace.md) | UseTwoLevelNamespace | Warning | Use two-level namespace |
| [AD5009](../AD5009.DoNotUseWeakDylib.md) | DoNotUseWeakDylib | Warning | Avoid weak dylib linking |
| [AD5018](../AD5018.RequireMinimumOSVersion.md) | RequireMinimumOSVersion | Warning | Require minimum OS version |
| [AD5019](../AD5019.UseRestrictSegment.md) | UseRestrictSegment | Note | Use __RESTRICT segment |

## Clang-Specific

| Rule | Name | Severity | Description |
|------|------|----------|-------------|
| [AD5008](../AD5008.EnableClangSafeStackMachO.md) | EnableClangSafeStackMachO | Warning | Enable SafeStack |
| [AD5027](../AD5027.EnableSpeculativeLoadHardeningMachO.md) | EnableSpeculativeLoadHardeningMachO | Warning | Speculative load hardening |

## Objective-C

| Rule | Name | Severity | Description |
|------|------|----------|-------------|
| [AD5010](../AD5010.EnableAutomaticReferenceCounting.md) | EnableAutomaticReferenceCounting | Warning | Enable ARC |

## Compiler & Optimization

| Rule | Name | Severity | Description |
|------|------|----------|-------------|
| [AD5017](../AD5017.EnableLTOMachO.md) | EnableLTOMachO | Note | Enable LTO |
| [AD5028](../AD5028.EnableOptimizationMachO.md) | EnableOptimizationMachO | Note | Enable optimization |
| [AD5030](../AD5030.EnableExceptionHandlingMachO.md) | EnableExceptionHandlingMachO | Warning | Exception handling |
| [AD5040](../AD5040.DoNotUseUncheckedOptimization.md) | DoNotUseUncheckedOptimization | Warning | Safe optimizations |

## Rust-Specific

| Rule | Name | Severity | Description |
|------|------|----------|-------------|
| [AD5020](../AD5020.RustEnableSanitizersMachO.md) | RustEnableSanitizersMachO | Note | Rust sanitizers |
| [AD5021](../AD5021.RustEnableSecureSourceHashMachO.md) | RustEnableSecureSourceHashMachO | Note | Secure source hashing |
| [AD5022](../AD5022.RustMachOEnableLTO.md) | RustMachOEnableLTO | Note | Rust LTO |

## Sanitizers (Development)

| Rule | Name | Severity | Description |
|------|------|----------|-------------|
| [AD5014](../AD5014.UseAddressSanitizer.md) | UseAddressSanitizer | Note | AddressSanitizer |
| [AD5023](../AD5023.EnableUBSanMachO.md) | EnableUBSanMachO | Note | UndefinedBehaviorSanitizer |

## Supply Chain

| Rule | Name | Severity | Description |
|------|------|----------|-------------|
| [AD5013](../AD5013.DoNotUseBannedApisMachO.md) | DoNotUseBannedApisMachO | Warning | Banned API usage |
| [AD5015](../AD5015.DoNotStaticallyLinkOpenSSL.md) | DoNotStaticallyLinkOpenSSL | Warning | Don't statically link OpenSSL |
| [AD5016](../AD5016.NoUnicodeSymbolsMachO.md) | NoUnicodeSymbolsMachO | Warning | No Unicode in symbols |
