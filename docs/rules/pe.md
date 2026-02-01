# PE (Windows) Security Rules

Rules for analyzing Windows PE (Portable Executable) binaries including executables (.exe) and dynamic libraries (.dll).

## Memory Protection

| Rule | Name | Severity | Description |
|------|------|----------|-------------|
| [AD2001](../AD2001.LoadImagesAboveFourGigabyteAddress.md) | LoadImagesAboveFourGigabyteAddress | Warning | Enable /LARGEADDRESSAWARE for 64-bit ASLR |
| [AD2009](../AD2009.EnableAddressSpaceLayoutRandomization.md) | EnableAddressSpaceLayoutRandomization | Error | Enable ASLR (/DYNAMICBASE) |
| [AD2015](../AD2015.EnableHighEntropyVirtualAddresses.md) | EnableHighEntropyVirtualAddresses | Warning | Enable high-entropy ASLR |
| [AD2016](../AD2016.MarkImageAsNXCompatible.md) | MarkImageAsNXCompatible | Error | Enable DEP/NX (/NXCOMPAT) |

## Stack Protection

| Rule | Name | Severity | Description |
|------|------|----------|-------------|
| [AD2011](../AD2011.EnableStackProtection.md) | EnableStackProtection | Error | Enable stack canaries (/GS) |
| [AD2012](../AD2012.DoNotModifyStackProtectionCookie.md) | DoNotModifyStackProtectionCookie | Error | Don't modify security cookie |
| [AD2013](../AD2013.InitializeStackProtection.md) | InitializeStackProtection | Error | Initialize stack protection |
| [AD2014](../AD2014.DoNotDisableStackProtectionForFunctions.md) | DoNotDisableStackProtectionForFunctions | Warning | Don't disable /GS for functions |
| [AD2018](../AD2018.EnableSafeSEH.md) | EnableSafeSEH | Error | Enable SafeSEH (32-bit) |
| [AD2031](../AD2031.EnableControlStackChecking.md) | EnableControlStackChecking | Warning | Enable /RTC stack checking |

## Control Flow

| Rule | Name | Severity | Description |
|------|------|----------|-------------|
| [AD2008](../AD2008.EnableControlFlowGuard.md) | EnableControlFlowGuard | Error | Enable CFG (/guard:cf) |
| [AD2025](../AD2025.EnableShadowStack.md) | EnableShadowStack | Warning | Enable CET Shadow Stack |
| [AD2030](../AD2030.EnableCastGuard.md) | EnableCastGuard | Warning | Enable CastGuard (/guard:cast) |
| [AD2054](../AD2054.EnableReturnFlowGuard.md) | EnableReturnFlowGuard | Note | Enable RFG (deprecated) |

## Compiler Settings

| Rule | Name | Severity | Description |
|------|------|----------|-------------|
| [AD2006](../AD2006.BuildWithSecureTools.md) | BuildWithSecureTools | Error | Use up-to-date compiler |
| [AD2007](../AD2007.EnableCriticalCompilerWarnings.md) | EnableCriticalCompilerWarnings | Warning | Enable critical warnings |
| [AD2024](../AD2024.EnableSpectreMitigations.md) | EnableSpectreMitigations | Warning | Enable Spectre mitigations |
| [AD2026](../AD2026.EnableMicrosoftCompilerSdlSwitch.md) | EnableMicrosoftCompilerSdlSwitch | Warning | Enable /sdl |

## Code Signing

| Rule | Name | Severity | Description |
|------|------|----------|-------------|
| [AD2022](../AD2022.SignSecurely.md) | SignSecurely | Error | Use SHA-256 for signing |
| [AD2052](../AD2052.RequireAuthenticode.md) | RequireAuthenticode | Warning | Require Authenticode signature |
| [AD2029](../AD2029.EnableIntegrityCheck.md) | EnableIntegrityCheck | Warning | Enable /INTEGRITYCHECK |

## Section Properties

| Rule | Name | Severity | Description |
|------|------|----------|-------------|
| [AD2010](../AD2010.DoNotMarkImportsSectionAsExecutable.md) | DoNotMarkImportsSectionAsExecutable | Error | Imports should not be executable |
| [AD2019](../AD2019.DoNotMarkWritableSectionsAsShared.md) | DoNotMarkWritableSectionsAsShared | Error | Writable sections shouldn't be shared |
| [AD2021](../AD2021.DoNotMarkWritableSectionsAsExecutable.md) | DoNotMarkWritableSectionsAsExecutable | Error | No W+X sections |

## GCC/Clang on Windows (DWARF)

| Rule | Name | Severity | Description |
|------|------|----------|-------------|
| [AD2033](../AD2033.PeEnableStackProtectorDwarf.md) | PeEnableStackProtectorDwarf | Warning | GCC/MinGW stack protector |
| [AD2036](../AD2036.PeEnableControlFlowIntegrity.md) | PeEnableControlFlowIntegrity | Warning | Clang CFI |
| [AD2037](../AD2037.PeEnableStackClashProtection.md) | PeEnableStackClashProtection | Warning | Stack clash protection |
| [AD2038](../AD2038.PeEnableClangSafeStack.md) | PeEnableClangSafeStack | Warning | Clang SafeStack |

## ARM64 Windows

| Rule | Name | Severity | Description |
|------|------|----------|-------------|
| [AD2039](../AD2039.PeEnableArmPAC.md) | PeEnableArmPAC | Warning | ARM Pointer Authentication |
| [AD2040](../AD2040.PeEnableArmBTI.md) | PeEnableArmBTI | Warning | ARM Branch Target Identification |
| [AD2047](../AD2047.PeEnableShadowCallStack.md) | PeEnableShadowCallStack | Warning | Shadow Call Stack |
