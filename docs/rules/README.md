# Aldur Rules Documentation

This directory contains detailed documentation for all security rules implemented by Aldur.

## Overview

Aldur implements **119 security rules** across three binary formats:

- **PE (Windows)**: 49 rules (AD2xxx, AD4001, AD6xxx series)
- **ELF (Linux/Unix)**: 39 rules (AD3xxx, AD4002 series)
- **Mach-O (macOS)**: 31 rules (AD5xxx series)

## Standards Compliance

See [OpenSSF-Compliance.md](OpenSSF-Compliance.md) for a detailed comparison of Aldur coverage against the [OpenSSF Compiler Options Hardening Guide for C and C++](https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html).

## Rule Severity Levels

| Level | Description |
|-------|-------------|
| **Error** | Critical security issue that should be fixed |
| **Warning** | Important security concern that should be addressed |
| **Note** | Informational finding or best practice recommendation |

## Quick Reference

### PE Rules (Windows)

| Rule | Name | Level | Description |
|------|------|-------|-------------|
| [AD2001](AD2001.LoadImagesAboveFourGigabyteAddress.md) | LoadImagesAboveFourGigabyteAddress | Error | 64-bit images should use high addresses |
| [AD2004](AD2004.EnableSecureSourceCodeHashing.md) | EnableSecureSourceCodeHashing | Warning | Use SHA-256 for PDB source hashing |
| [AD2006](AD2006.BuildWithSecureTools.md) | BuildWithSecureTools | Error | Use up-to-date compiler toolchain |
| [AD2007](AD2007.EnableCriticalCompilerWarnings.md) | EnableCriticalCompilerWarnings | Warning | Enable critical security warnings |
| [AD2008](AD2008.EnableControlFlowGuard.md) | EnableControlFlowGuard | Error | Enable CFG protection |
| [AD2009](AD2009.EnableAddressSpaceLayoutRandomization.md) | EnableAddressSpaceLayoutRandomization | Error | Enable ASLR with /DYNAMICBASE |
| [AD2010](AD2010.DoNotMarkImportsSectionAsExecutable.md) | DoNotMarkImportsSectionAsExecutable | Error | Imports section should not be executable |
| [AD2011](AD2011.EnableStackProtection.md) | EnableStackProtection | Error | Enable /GS stack protection |
| [AD2012](AD2012.DoNotModifyStackProtectionCookie.md) | DoNotModifyStackProtectionCookie | Error | Use default security cookie |
| [AD2013](AD2013.InitializeStackProtection.md) | InitializeStackProtection | Error | Properly initialize stack cookie |
| [AD2014](AD2014.DoNotDisableStackProtectionForFunctions.md) | DoNotDisableStackProtectionForFunctions | Warning | Don't disable /GS per-function |
| [AD2015](AD2015.EnableHighEntropyVirtualAddresses.md) | EnableHighEntropyVirtualAddresses | Error | Enable high-entropy ASLR |
| [AD2016](AD2016.MarkImageAsNXCompatible.md) | MarkImageAsNXCompatible | Error | Enable DEP/NX |
| [AD2018](AD2018.EnableSafeSEH.md) | EnableSafeSEH | Error | Enable SafeSEH (32-bit) |
| [AD2019](AD2019.DoNotMarkWritableSectionsAsShared.md) | DoNotMarkWritableSectionsAsShared | Error | No shared writable sections |
| [AD2021](AD2021.DoNotMarkWritableSectionsAsExecutable.md) | DoNotMarkWritableSectionsAsExecutable | Error | No W+X sections |
| [AD2024](AD2024.EnableSpectreMitigations.md) | EnableSpectreMitigations | Warning | Enable /Qspectre |
| [AD2025](AD2025.EnableShadowStack.md) | EnableShadowStack | Warning | Enable CET Shadow Stack |
| [AD2026](AD2026.EnableMicrosoftCompilerSdlSwitch.md) | EnableMicrosoftCompilerSdlSwitch | Warning | Enable /sdl flag |
| [AD2027](AD2027.EnableSourceLink.md) | EnableSourceLink | Note | Include SourceLink info |
| [AD2029](AD2029.EnableIntegrityCheck.md) | EnableIntegrityCheck | Error | Enable /INTEGRITYCHECK |
| [AD2030](AD2030.EnableCastGuard.md) | EnableCastGuard | Warning | Enable /guard:ehcont |
| [AD2031](AD2031.EnableControlStackChecking.md) | EnableControlStackChecking | Warning | Enable /RTC stack checking |
| [AD2032](AD2032.DotNetEnableHighEntropyVA.md) | DotNetEnableHighEntropyVA | Error | .NET high-entropy VA |
| [AD2047](AD2047.PeEnableShadowCallStack.md) | PeEnableShadowCallStack | Warning | Enable Shadow Call Stack |
| [AD2048](AD2048.PeEnableStackVariableInitialization.md) | PeEnableStackVariableInitialization | Warning | Enable stack variable init |
| [AD4001](AD4001.ReportPECompilerData.md) | ReportPECompilerData | Note | Report compiler info from PDB |
| [AD6001](AD6001.DisableIncrementalLinkingInReleaseBuilds.md) | DisableIncrementalLinkingInReleaseBuilds | Warning | Disable incremental linking |
| [AD6002](AD6002.EliminateDuplicateStrings.md) | EliminateDuplicateStrings | Warning | Enable /GF string pooling |
| [AD6004](AD6004.EnableComdatFolding.md) | EnableComdatFolding | Warning | Enable /OPT:ICF COMDAT folding |
| [AD6005](AD6005.EnableOptimizeReferences.md) | EnableOptimizeReferences | Warning | Enable /OPT:REF dead code removal |
| [AD6006](AD6006.EnableLinkTimeCodeGeneration.md) | EnableLinkTimeCodeGeneration | Warning | Enable LTCG optimization |

### ELF Rules (Linux/Unix)

| Rule | Name | Level | Description |
|------|------|-------|-------------|
| [AD3001](AD3001.EnablePositionIndependentExecutable.md) | EnablePositionIndependentExecutable | Error | Enable PIE for ASLR |
| [AD3002](AD3002.DoNotMarkStackAsExecutable.md) | DoNotMarkStackAsExecutable | Error | Stack should not be executable |
| [AD3003](AD3003.EnableStackProtector.md) | EnableStackProtector | Error | Enable stack canary |
| [AD3004](AD3004.GenerateRequiredSymbolFormat.md) | GenerateRequiredSymbolFormat | Warning | Use DWARF debug symbols |
| [AD3005](AD3005.EnableStackClashProtection.md) | EnableStackClashProtection | Warning | Enable stack clash protection |
| [AD3006](AD3006.EnableNonExecutableStack.md) | EnableNonExecutableStack | Error | Mark stack non-executable |
| [AD3010](AD3010.EnableReadOnlyRelocations.md) | EnableReadOnlyRelocations | Error | Enable RELRO |
| [AD3011](AD3011.EnableBindNow.md) | EnableBindNow | Warning | Enable full RELRO (BIND_NOW) |
| [AD3012](AD3012.DoNotUseRpath.md) | DoNotUseRpath | Warning | Avoid DT_RPATH (use RUNPATH) |
| [AD3013](AD3013.ValidateRunpath.md) | ValidateRunpath | Warning | Validate RUNPATH entries |
| [AD3014](AD3014.NoTextRelocations.md) | NoTextRelocations | Error | No text relocations |
| [AD3015](AD3015.EnableIntelCET.md) | EnableIntelCET | Warning | Enable Intel CET (x86_64) |
| [AD3016](AD3016.EnableIntelShadowStack.md) | EnableIntelShadowStack | Warning | Enable Intel Shadow Stack |
| [AD3017](AD3017.EnableArmBTI.md) | EnableArmBTI | Warning | Enable ARM BTI (AArch64) |
| [AD3018](AD3018.EnableArmPAC.md) | EnableArmPAC | Warning | Enable ARM PAC (AArch64) |
| [AD3019](AD3019.EnableLTO.md) | EnableLTO | Note | Enable Link-Time Optimization |
| [AD3020](AD3020.EnableOptimization.md) | EnableOptimization | Note | Enable optimization for FORTIFY |
| [AD3021](AD3021.NoUnicodeSymbols.md) | NoUnicodeSymbols | Warning | No Unicode/Trojan Source in symbols |
| [AD3022](AD3022.WritableGotProtection.md) | WritableGotProtection | Error | GOT should be read-only |
| [AD3023](AD3023.ProperLoadSegments.md) | ProperLoadSegments | Error | No RWX load segments |
| [AD3024](AD3024.RestrictDlopen.md) | RestrictDlopen | Note | Restrict dlopen() with DF_1_NOOPEN |
| [AD3025](AD3025.EnableExceptionHandling.md) | EnableExceptionHandling | Note | Include .eh_frame for thread safety |
| [AD3030](AD3030.UseGccCheckedFunctions.md) | UseGccCheckedFunctions | Warning | Enable FORTIFY_SOURCE |
| [AD3031](AD3031.EnableClangSafeStack.md) | EnableClangSafeStack | Warning | Enable Clang SafeStack |
| [AD3032](AD3032.EnableSpeculativeLoadHardening.md) | EnableSpeculativeLoadHardening | Warning | Enable SLH |
| [AD3033](AD3033.RustEnableCET.md) | RustEnableCET | Warning | Rust: Enable CET |
| [AD3034](AD3034.RustEnableControlFlowGuard.md) | RustEnableControlFlowGuard | Warning | Rust: Enable CFG (PE/Windows) |
| [AD3035](AD3035.RustEnableSecureSourceHash.md) | RustEnableSecureSourceHash | Warning | Rust: Secure source hash |
| [AD3036](AD3036.EnableControlFlowIntegrity.md) | EnableControlFlowIntegrity | Warning | Enable CFI (Clang) |
| [AD3037](AD3037.RustEnableSanitizers.md) | RustEnableSanitizers | Note | Rust: Enable sanitizers |
| [AD3038](AD3038.EnableUBSan.md) | EnableUBSan | Note | Enable UBSan |
| [AD3039](AD3039.EnableArmMTE.md) | EnableArmMTE | Note | Enable ARM MTE |
| [AD3040](AD3040.EnableAddressSanitizerELF.md) | EnableAddressSanitizerELF | Note | Enable ASan |
| [AD3041](AD3041.DoNotUseBannedApisELF.md) | DoNotUseBannedApisELF | Error | No banned APIs |
| [AD3042](AD3042.DoNotStaticallyLinkOpenSSLELF.md) | DoNotStaticallyLinkOpenSSLELF | Warning | No static OpenSSL |
| [AD3043](AD3043.EnableKernelCFI.md) | EnableKernelCFI | Note | Enable KCFI |
| [AD3044](AD3044.EnableShadowCallStack.md) | EnableShadowCallStack | Warning | Enable Shadow Call Stack |
| [AD3045](AD3045.EnableStackVariableInitialization.md) | EnableStackVariableInitialization | Note | Enable stack var init |
| [AD4002](AD4002.ReportElfOrMachoCompilerData.md) | ReportElfOrMachoCompilerData | Note | Report ELF/Mach-O binary info |

### Mach-O Rules (macOS)

| Rule | Name | Level | Description |
|------|------|-------|-------------|
| [AD5001](AD5001.EnablePositionIndependentExecutableMachO.md) | EnablePositionIndependentExecutableMachO | Error | Enable PIE for ASLR |
| [AD5002](AD5002.DoNotAllowExecutableStack.md) | DoNotAllowExecutableStack | Error | No executable stack |
| [AD5003](AD5003.EnableStackProtectorMachO.md) | EnableStackProtectorMachO | Error | Enable stack protector |
| [AD5004](AD5004.UseFortifiedFunctionsMachO.md) | UseFortifiedFunctionsMachO | Warning | Use FORTIFY_SOURCE |
| [AD5005](AD5005.DoNotAllowExecutableHeap.md) | DoNotAllowExecutableHeap | Error | No executable heap |
| [AD5006](AD5006.UseTwoLevelNamespace.md) | UseTwoLevelNamespace | Warning | Use two-level namespace |
| [AD5007](AD5007.EnableArmPACMachO.md) | EnableArmPACMachO | Warning | Enable ARM PAC |
| [AD5008](AD5008.EnableClangSafeStackMachO.md) | EnableClangSafeStackMachO | Warning | Enable Clang SafeStack |
| [AD5009](AD5009.DoNotUseWeakDylib.md) | DoNotUseWeakDylib | Warning | No weak dylib |
| [AD5010](AD5010.EnableAutomaticReferenceCounting.md) | EnableAutomaticReferenceCounting | Note | Enable ARC |
| [AD5011](AD5011.RequireCodeSignature.md) | RequireCodeSignature | Error | Require code signature |
| [AD5012](AD5012.ValidateSegmentPermissions.md) | ValidateSegmentPermissions | Error | No RWX segments |
| [AD5013](AD5013.DoNotUseBannedApis.md) | DoNotUseBannedApis | Error | No banned APIs |
| [AD5014](AD5014.UseAddressSanitizer.md) | UseAddressSanitizer | Note | Enable ASan |
| [AD5015](AD5015.DoNotStaticallyLinkOpenSSL.md) | DoNotStaticallyLinkOpenSSL | Warning | No static OpenSSL |
| [AD5016](AD5016.NoUnicodeSymbolsMachO.md) | NoUnicodeSymbolsMachO | Warning | No Unicode symbols |
| [AD5017](AD5017.EnableLTOMachO.md) | EnableLTOMachO | Note | Enable LTO |
| [AD5018](AD5018.RequireMinimumOSVersion.md) | RequireMinimumOSVersion | Warning | Require min OS version |
| [AD5019](AD5019.UseRestrictSegment.md) | UseRestrictSegment | Note | Use __RESTRICT segment |

## Rule Categories

### Memory Protection
- AD2016, AD3002, AD3006, AD5002 - Non-executable stack/DEP
- AD2021, AD2010, AD2019 - Section permissions
- AD3010, AD3011 - RELRO protection

### Address Space Layout Randomization (ASLR)
- AD2001, AD2009, AD2015 - Windows ASLR
- AD3001, AD5001 - ELF/Mach-O PIE

### Stack Protection
- AD2011, AD2012, AD2013, AD2014 - Windows /GS
- AD3003, AD3005 - Linux stack protector
- AD3031 - Clang SafeStack

### Control Flow Integrity
- AD2008 - Control Flow Guard
- AD2025 - CET Shadow Stack
- AD2018 - SafeSEH
- AD3015, AD3016 - Intel CET (IBT + Shadow Stack)
- AD3017, AD3018 - ARM BTI/PAC
- AD3036 - Clang CFI
- AD3043 - Kernel CFI
- AD3044, AD2047 - Shadow Call Stack

### Compiler Security
- AD2006 - Secure compiler version
- AD2007 - Compiler warnings
- AD2024 - Spectre mitigations
- AD2026 - SDL checks
- AD3019, AD5017 - Link-Time Optimization
- AD3020 - Optimization level
- AD3030, AD5004 - FORTIFY_SOURCE
- AD3032 - Speculative Load Hardening

### Sanitizers
- AD3038 - UBSan
- AD3040, AD5014 - AddressSanitizer
- AD3031, AD5008 - Clang SafeStack
- AD3037 - Rust Sanitizers

### Supply Chain Security
- AD3041, AD5013 - Banned APIs
- AD3042, AD5015 - Static OpenSSL linking
- AD3021, AD5016 - Unicode/Trojan Source

### Rust-Specific
- AD3033 - Rust CET
- AD3034 - Rust Control Flow Guard
- AD3035 - Rust Secure Source Hash
- AD3037 - Rust Sanitizers

### Link Security
- AD3012, AD3013 - RPATH/RUNPATH validation
- AD3014 - Text relocations
- AD3022 - GOT protection
- AD3023 - Segment permissions

### Debugging & Diagnostics
- AD2004 - Secure source hashing
- AD2027 - SourceLink
- AD3004 - DWARF symbols

## Further Reading

- [OpenSSF Compiler Options Hardening Guide](https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html) - Industry standard hardening recommendations
- [Microsoft BinSkim Documentation](https://github.com/microsoft/BinSkim/blob/main/docs/BinSkimRules.md) - Original C# implementation
- [checksec.sh](https://github.com/slimm609/checksec.sh) - Linux binary security checker
- [Hardening ELF Binaries](https://wiki.gentoo.org/wiki/Hardened/Toolchain)
- [Windows Security Features](https://docs.microsoft.com/en-us/cpp/build/reference/linker-options)
