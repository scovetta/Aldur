//! PE (Windows) security rules

mod ad2001_load_images_above_4gb;
mod ad2004_enable_secure_source_hashing;
mod ad2006_build_with_secure_tools;
mod ad2007_enable_critical_compiler_warnings;
mod ad2008_enable_control_flow_guard;
mod ad2009_enable_aslr;
mod ad2010_do_not_mark_imports_executable;
mod ad2011_enable_stack_protection;
mod ad2012_do_not_modify_stack_protection_cookie;
mod ad2013_initialize_stack_protection;
mod ad2014_do_not_disable_stack_protection_for_functions;
mod ad2015_enable_high_entropy_va;
mod ad2016_mark_image_as_nx_compatible;
mod ad2018_enable_safe_seh;
mod ad2019_do_not_mark_writable_sections_shared;
mod ad2021_do_not_mark_writable_sections_executable;
mod ad2024_enable_spectre_mitigations;
mod ad2025_enable_shadow_stack;
mod ad2026_enable_sdl;
mod ad2027_enable_source_link;
mod ad2029_enable_integrity_check;
mod ad2030_enable_cast_guard;
mod ad2031_enable_control_stack_checking;
mod ad2032_dotnet_high_entropy_va;
mod ad2033_pe_enable_stack_protector_dwarf;
mod ad2034_pe_enable_lto_dwarf;
mod ad2035_pe_report_compiler_data_dwarf;
mod ad2036_pe_enable_cfi;
mod ad2037_pe_enable_stack_clash_protection;
mod ad2038_pe_enable_clang_safestack;
mod ad2039_pe_enable_arm_pac;
mod ad2040_pe_enable_arm_bti;
mod ad2041_rust_enable_sanitizers_pe;
mod ad2042_no_unicode_symbols;
mod ad2043_do_not_use_banned_apis;
mod ad2044_do_not_statically_link_openssl;
mod ad2045_enable_ubsan;
mod ad2046_enable_address_sanitizer;
mod ad2047_pe_enable_shadow_call_stack;
mod ad2048_pe_enable_stack_variable_init;
mod ad2050_do_not_use_custom_base_address;
mod ad2051_check_minimum_library_versions;
mod ad2052_require_authenticode;
mod ad2053_allow_isolation;
mod ad2054_enable_rfg;
mod ad2060_detect_packed_binary;
mod ad3034_rust_enable_cfg;
mod ad4001_report_pe_compiler_data;
mod ad6001_disable_incremental_linking;
mod ad6002_eliminate_duplicate_strings;
mod ad6004_enable_comdat_folding;
mod ad6005_enable_optimize_references;
mod ad6006_enable_ltcg;
mod msvc_utils;

pub use ad2001_load_images_above_4gb::LoadImagesAboveFourGigabyteAddress;
pub use ad2004_enable_secure_source_hashing::EnableSecureSourceCodeHashing;
pub use ad2006_build_with_secure_tools::BuildWithSecureTools;
pub use ad2007_enable_critical_compiler_warnings::EnableCriticalCompilerWarnings;
pub use ad2008_enable_control_flow_guard::EnableControlFlowGuard;
pub use ad2009_enable_aslr::EnableAddressSpaceLayoutRandomization;
pub use ad2010_do_not_mark_imports_executable::DoNotMarkImportsSectionAsExecutable;
pub use ad2011_enable_stack_protection::EnableStackProtection;
pub use ad2012_do_not_modify_stack_protection_cookie::DoNotModifyStackProtectionCookie;
pub use ad2013_initialize_stack_protection::InitializeStackProtection;
pub use ad2014_do_not_disable_stack_protection_for_functions::DoNotDisableStackProtectionForFunctions;
pub use ad2015_enable_high_entropy_va::EnableHighEntropyVirtualAddresses;
pub use ad2016_mark_image_as_nx_compatible::MarkImageAsNXCompatible;
pub use ad2018_enable_safe_seh::EnableSafeSEH;
pub use ad2019_do_not_mark_writable_sections_shared::DoNotMarkWritableSectionsAsShared;
pub use ad2021_do_not_mark_writable_sections_executable::DoNotMarkWritableSectionsAsExecutable;
pub use ad2024_enable_spectre_mitigations::EnableSpectreMitigations;
pub use ad2025_enable_shadow_stack::EnableShadowStack;
pub use ad2026_enable_sdl::EnableMicrosoftCompilerSdlSwitch;
pub use ad2027_enable_source_link::EnableSourceLink;
pub use ad2029_enable_integrity_check::EnableIntegrityCheck;
pub use ad2030_enable_cast_guard::EnableCastGuard;
pub use ad2031_enable_control_stack_checking::EnableControlStackChecking;
pub use ad2032_dotnet_high_entropy_va::DotNetEnableHighEntropyVA;
pub use ad2033_pe_enable_stack_protector_dwarf::PeEnableStackProtectorDwarf;
pub use ad2034_pe_enable_lto_dwarf::PeEnableLtoDwarf;
pub use ad2035_pe_report_compiler_data_dwarf::PeReportCompilerDataDwarf;
pub use ad2036_pe_enable_cfi::PeEnableControlFlowIntegrity;
pub use ad2037_pe_enable_stack_clash_protection::PeEnableStackClashProtection;
pub use ad2038_pe_enable_clang_safestack::PeEnableClangSafeStack;
pub use ad2039_pe_enable_arm_pac::PeEnableArmPAC;
pub use ad2040_pe_enable_arm_bti::PeEnableArmBTI;
pub use ad2041_rust_enable_sanitizers_pe::RustEnableSanitizersPE;
pub use ad2042_no_unicode_symbols::NoUnicodeSymbolsPE;
pub use ad2043_do_not_use_banned_apis::DoNotUseBannedApisPE;
pub use ad2044_do_not_statically_link_openssl::DoNotStaticallyLinkOpenSSLPE;
pub use ad2045_enable_ubsan::EnableUBSanPE;
pub use ad2046_enable_address_sanitizer::EnableAddressSanitizerPE;
pub use ad2047_pe_enable_shadow_call_stack::PeEnableShadowCallStack;
pub use ad2048_pe_enable_stack_variable_init::PeEnableStackVariableInitialization;
pub use ad2050_do_not_use_custom_base_address::DoNotUseCustomBaseAddress;
pub use ad2051_check_minimum_library_versions::CheckMinimumLibraryVersions;
pub use ad2052_require_authenticode::RequireAuthenticode;
pub use ad2053_allow_isolation::AllowIsolation;
pub use ad2054_enable_rfg::EnableReturnFlowGuard;
pub use ad2060_detect_packed_binary::DetectPackedBinaryPE;
pub use ad3034_rust_enable_cfg::RustEnableControlFlowGuard;
pub use ad4001_report_pe_compiler_data::ReportPECompilerData;
pub use ad6001_disable_incremental_linking::DisableIncrementalLinkingInReleaseBuilds;
pub use ad6002_eliminate_duplicate_strings::EliminateDuplicateStrings;
pub use ad6004_enable_comdat_folding::EnableComdatFolding;
pub use ad6005_enable_optimize_references::EnableOptimizeReferences;
pub use ad6006_enable_ltcg::EnableLinkTimeCodeGeneration;

use aldur_core::Rule;

/// Get all PE rules
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(LoadImagesAboveFourGigabyteAddress::new()),
        Box::new(EnableSecureSourceCodeHashing::new()),
        Box::new(BuildWithSecureTools::new()),
        Box::new(EnableCriticalCompilerWarnings::new()),
        Box::new(EnableControlFlowGuard::new()),
        Box::new(EnableAddressSpaceLayoutRandomization::new()),
        Box::new(DoNotMarkImportsSectionAsExecutable::new()),
        Box::new(EnableStackProtection::new()),
        Box::new(DoNotModifyStackProtectionCookie::new()),
        Box::new(InitializeStackProtection::new()),
        Box::new(DoNotDisableStackProtectionForFunctions::new()),
        Box::new(EnableHighEntropyVirtualAddresses::new()),
        Box::new(MarkImageAsNXCompatible::new()),
        Box::new(EnableSafeSEH::new()),
        Box::new(DoNotMarkWritableSectionsAsShared::new()),
        Box::new(DoNotMarkWritableSectionsAsExecutable::new()),
        Box::new(EnableSpectreMitigations::new()),
        Box::new(EnableShadowStack::new()),
        Box::new(EnableMicrosoftCompilerSdlSwitch::new()),
        Box::new(EnableSourceLink::new()),
        Box::new(EnableIntegrityCheck::new()),
        Box::new(EnableCastGuard::new()),
        Box::new(EnableControlStackChecking::new()),
        Box::new(DotNetEnableHighEntropyVA::new()),
        Box::new(PeEnableStackProtectorDwarf::new()),
        Box::new(PeEnableLtoDwarf::new()),
        Box::new(PeReportCompilerDataDwarf::new()),
        Box::new(PeEnableControlFlowIntegrity::new()),
        Box::new(PeEnableStackClashProtection::new()),
        Box::new(PeEnableClangSafeStack::new()),
        Box::new(PeEnableArmPAC::new()),
        Box::new(PeEnableArmBTI::new()),
        Box::new(RustEnableControlFlowGuard::new()),
        Box::new(RustEnableSanitizersPE::new()),
        Box::new(NoUnicodeSymbolsPE::new()),
        Box::new(DoNotUseBannedApisPE::new()),
        Box::new(DoNotStaticallyLinkOpenSSLPE::new()),
        Box::new(EnableUBSanPE::new()),
        Box::new(EnableAddressSanitizerPE::new()),
        Box::new(PeEnableShadowCallStack::new()),
        Box::new(PeEnableStackVariableInitialization::new()),
        Box::new(ReportPECompilerData::new()),
        Box::new(DisableIncrementalLinkingInReleaseBuilds::new()),
        Box::new(EliminateDuplicateStrings::new()),
        Box::new(EnableComdatFolding::new()),
        Box::new(EnableOptimizeReferences::new()),
        Box::new(EnableLinkTimeCodeGeneration::new()),
        Box::new(DoNotUseCustomBaseAddress::new()),
        Box::new(CheckMinimumLibraryVersions::new()),
        Box::new(RequireAuthenticode::new()),
        Box::new(AllowIsolation::new()),
        Box::new(EnableReturnFlowGuard::new()),
        Box::new(DetectPackedBinaryPE::new()),
    ]
}
