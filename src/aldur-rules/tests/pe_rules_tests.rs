//! Integration tests for PE (Windows) security rules
//!
//! These tests verify that PE rules correctly detect security issues
//! in test binaries cross-compiled with MinGW.

use aldur_core::{AnalysisApplicability, AnalysisConfig, AnalysisContext, Binary, FailureLevel, ResultKind, Rule};
use aldur_parsers::PeBinary;
use std::path::PathBuf;
use std::sync::Arc;

/// Path to PE test fixtures directory
fn pe_fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test-fixtures")
        .join("pe")
}

/// Create an analysis context for testing PE binaries
fn create_pe_context(binary_name: &str) -> Option<AnalysisContext> {
    let path = pe_fixtures_dir().join(binary_name);
    if !path.exists() {
        return None;
    }
    let binary = PeBinary::load(&path).ok()?;
    let mut context = AnalysisContext::new(path, AnalysisConfig::default());
    context.set_binary(Arc::new(binary) as Arc<dyn Binary>);
    Some(context)
}

/// Helper to run a PE rule and return results
fn run_pe_rule(rule: &dyn Rule, binary_name: &str) -> Option<(AnalysisApplicability, Vec<aldur_core::RuleResult>)> {
    let mut context = create_pe_context(binary_name)?;
    let (applicability, _) = rule.can_analyze(&context);
    if applicability == AnalysisApplicability::ApplicableToSpecifiedTarget {
        rule.analyze(&mut context);
    }
    Some((applicability, context.take_results()))
}

/// Verify rule descriptor is properly configured
fn verify_rule_descriptor(rule: &dyn Rule, expected_id: &str, expected_name: &str) {
    let desc = rule.descriptor();
    assert_eq!(desc.id, expected_id, "Rule ID mismatch");
    assert_eq!(desc.name, expected_name, "Rule name mismatch");
    assert!(!desc.short_description.is_empty(), "Short description should not be empty");
    assert!(!desc.full_description.is_empty(), "Full description should not be empty");
}

mod ad2001_load_images_above_4gb_tests {
    use super::*;
    use aldur_rules::pe::LoadImagesAboveFourGigabyteAddress;

    #[test]
    fn test_rule_descriptor() {
        let rule = LoadImagesAboveFourGigabyteAddress::new();
        verify_rule_descriptor(&rule, "AD2001", "LoadImagesAboveFourGigabyteAddress");
    }

    #[test]
    fn test_default_level() {
        let rule = LoadImagesAboveFourGigabyteAddress::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Error);
    }

    #[test]
    fn test_has_messages() {
        let rule = LoadImagesAboveFourGigabyteAddress::new();
        let desc = rule.descriptor();
        assert!(desc.messages.contains_key("Pass"), "Should have Pass message");
        assert!(desc.messages.contains_key("Error"), "Should have Error message");
    }
}

mod ad2004_secure_source_hashing_tests {
    use super::*;
    use aldur_rules::pe::EnableSecureSourceCodeHashing;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableSecureSourceCodeHashing::new();
        verify_rule_descriptor(&rule, "AD2004", "EnableSecureSourceCodeHashing");
    }

    #[test]
    fn test_default_level() {
        let rule = EnableSecureSourceCodeHashing::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }

    #[test]
    fn test_has_not_applicable_not_msvc_message() {
        let rule = EnableSecureSourceCodeHashing::new();
        let desc = rule.descriptor();
        assert!(
            desc.messages.contains_key("NotApplicable_NotMsvc"),
            "Should have NotApplicable_NotMsvc message for non-MSVC binaries"
        );
    }

    #[test]
    fn test_has_required_messages() {
        let rule = EnableSecureSourceCodeHashing::new();
        let desc = rule.descriptor();
        assert!(desc.messages.contains_key("Pass"), "Should have Pass message");
        assert!(desc.messages.contains_key("Warning"), "Should have Warning message");
        assert!(desc.messages.contains_key("Error_NoPdb"), "Should have Error_NoPdb message");
    }
}

mod ad2006_build_with_secure_tools_tests {
    use super::*;
    use aldur_rules::pe::BuildWithSecureTools;

    #[test]
    fn test_rule_descriptor() {
        let rule = BuildWithSecureTools::new();
        verify_rule_descriptor(&rule, "AD2006", "BuildWithSecureTools");
    }

    #[test]
    fn test_default_level() {
        let rule = BuildWithSecureTools::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Error);
    }

    #[test]
    fn test_has_messages() {
        let rule = BuildWithSecureTools::new();
        let desc = rule.descriptor();
        assert!(desc.messages.contains_key("Pass"), "Should have Pass message");
    }
}

mod ad2007_critical_compiler_warnings_tests {
    use super::*;
    use aldur_rules::pe::EnableCriticalCompilerWarnings;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableCriticalCompilerWarnings::new();
        verify_rule_descriptor(&rule, "AD2007", "EnableCriticalCompilerWarnings");
    }

    #[test]
    fn test_default_level() {
        let rule = EnableCriticalCompilerWarnings::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad2008_control_flow_guard_tests {
    use super::*;
    use aldur_rules::pe::EnableControlFlowGuard;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableControlFlowGuard::new();
        verify_rule_descriptor(&rule, "AD2008", "EnableControlFlowGuard");
    }

    #[test]
    fn test_default_level() {
        let rule = EnableControlFlowGuard::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Error);
    }

    #[test]
    fn test_has_messages() {
        let rule = EnableControlFlowGuard::new();
        let desc = rule.descriptor();
        assert!(desc.messages.contains_key("Pass"), "Should have Pass message");
        assert!(desc.messages.contains_key("Error"), "Should have Error message");
    }
}

mod ad2009_aslr_tests {
    use super::*;
    use aldur_rules::pe::EnableAddressSpaceLayoutRandomization;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableAddressSpaceLayoutRandomization::new();
        verify_rule_descriptor(&rule, "AD2009", "EnableAddressSpaceLayoutRandomization");
    }

    #[test]
    fn test_default_level() {
        let rule = EnableAddressSpaceLayoutRandomization::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Error);
    }

    #[test]
    fn test_has_messages() {
        let rule = EnableAddressSpaceLayoutRandomization::new();
        let desc = rule.descriptor();
        assert!(desc.messages.contains_key("Pass"), "Should have Pass message");
        assert!(desc.messages.contains_key("Error_NotDynamicBase"), "Should have Error_NotDynamicBase message");
    }
}

mod ad2010_imports_executable_tests {
    use super::*;
    use aldur_rules::pe::DoNotMarkImportsSectionAsExecutable;

    #[test]
    fn test_rule_descriptor() {
        let rule = DoNotMarkImportsSectionAsExecutable::new();
        verify_rule_descriptor(&rule, "AD2010", "DoNotMarkImportsSectionAsExecutable");
    }

    #[test]
    fn test_default_level() {
        let rule = DoNotMarkImportsSectionAsExecutable::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Error);
    }
}

mod ad2011_stack_protection_tests {
    use super::*;
    use aldur_rules::pe::EnableStackProtection;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableStackProtection::new();
        verify_rule_descriptor(&rule, "AD2011", "EnableStackProtection");
    }

    #[test]
    fn test_default_level() {
        let rule = EnableStackProtection::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Error);
    }
}

mod ad2012_stack_cookie_tests {
    use super::*;
    use aldur_rules::pe::DoNotModifyStackProtectionCookie;

    #[test]
    fn test_rule_descriptor() {
        let rule = DoNotModifyStackProtectionCookie::new();
        verify_rule_descriptor(&rule, "AD2012", "DoNotModifyStackProtectionCookie");
    }

    #[test]
    fn test_default_level() {
        let rule = DoNotModifyStackProtectionCookie::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Error);
    }
}

mod ad2013_initialize_stack_protection_tests {
    use super::*;
    use aldur_rules::pe::InitializeStackProtection;

    #[test]
    fn test_rule_descriptor() {
        let rule = InitializeStackProtection::new();
        verify_rule_descriptor(&rule, "AD2013", "InitializeStackProtection");
    }

    #[test]
    fn test_default_level() {
        let rule = InitializeStackProtection::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Error);
    }
}

mod ad2014_stack_protection_functions_tests {
    use super::*;
    use aldur_rules::pe::DoNotDisableStackProtectionForFunctions;

    #[test]
    fn test_rule_descriptor() {
        let rule = DoNotDisableStackProtectionForFunctions::new();
        verify_rule_descriptor(&rule, "AD2014", "DoNotDisableStackProtectionForFunctions");
    }

    #[test]
    fn test_default_level() {
        let rule = DoNotDisableStackProtectionForFunctions::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad2015_high_entropy_va_tests {
    use super::*;
    use aldur_rules::pe::EnableHighEntropyVirtualAddresses;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableHighEntropyVirtualAddresses::new();
        verify_rule_descriptor(&rule, "AD2015", "EnableHighEntropyVirtualAddresses");
    }

    #[test]
    fn test_default_level() {
        let rule = EnableHighEntropyVirtualAddresses::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Error);
    }
}

mod ad2016_nx_compatible_tests {
    use super::*;
    use aldur_rules::pe::MarkImageAsNXCompatible;

    #[test]
    fn test_rule_descriptor() {
        let rule = MarkImageAsNXCompatible::new();
        verify_rule_descriptor(&rule, "AD2016", "MarkImageAsNXCompatible");
    }

    #[test]
    fn test_default_level() {
        let rule = MarkImageAsNXCompatible::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Error);
    }
}

mod ad2018_safe_seh_tests {
    use super::*;
    use aldur_rules::pe::EnableSafeSEH;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableSafeSEH::new();
        verify_rule_descriptor(&rule, "AD2018", "EnableSafeSEH");
    }

    #[test]
    fn test_default_level() {
        let rule = EnableSafeSEH::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Error);
    }
}

mod ad2019_writable_shared_tests {
    use super::*;
    use aldur_rules::pe::DoNotMarkWritableSectionsAsShared;

    #[test]
    fn test_rule_descriptor() {
        let rule = DoNotMarkWritableSectionsAsShared::new();
        verify_rule_descriptor(&rule, "AD2019", "DoNotMarkWritableSectionsAsShared");
    }

    #[test]
    fn test_default_level() {
        let rule = DoNotMarkWritableSectionsAsShared::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Error);
    }
}

mod ad2021_writable_executable_tests {
    use super::*;
    use aldur_rules::pe::DoNotMarkWritableSectionsAsExecutable;

    #[test]
    fn test_rule_descriptor() {
        let rule = DoNotMarkWritableSectionsAsExecutable::new();
        verify_rule_descriptor(&rule, "AD2021", "DoNotMarkWritableSectionsAsExecutable");
    }

    #[test]
    fn test_default_level() {
        let rule = DoNotMarkWritableSectionsAsExecutable::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Error);
    }
}

mod ad2024_spectre_mitigations_tests {
    use super::*;
    use aldur_rules::pe::EnableSpectreMitigations;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableSpectreMitigations::new();
        verify_rule_descriptor(&rule, "AD2024", "EnableSpectreMitigations");
    }

    #[test]
    fn test_default_level() {
        let rule = EnableSpectreMitigations::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad2025_shadow_stack_tests {
    use super::*;
    use aldur_rules::pe::EnableShadowStack;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableShadowStack::new();
        verify_rule_descriptor(&rule, "AD2025", "EnableShadowStack");
    }

    #[test]
    fn test_default_level() {
        let rule = EnableShadowStack::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad2026_sdl_switch_tests {
    use super::*;
    use aldur_rules::pe::EnableMicrosoftCompilerSdlSwitch;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableMicrosoftCompilerSdlSwitch::new();
        verify_rule_descriptor(&rule, "AD2026", "EnableMicrosoftCompilerSdlSwitch");
    }

    #[test]
    fn test_default_level() {
        let rule = EnableMicrosoftCompilerSdlSwitch::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad2027_source_link_tests {
    use super::*;
    use aldur_rules::pe::EnableSourceLink;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableSourceLink::new();
        verify_rule_descriptor(&rule, "AD2027", "EnableSourceLink");
    }

    #[test]
    fn test_default_level() {
        let rule = EnableSourceLink::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Note);
    }
}

mod ad2029_integrity_check_tests {
    use super::*;
    use aldur_rules::pe::EnableIntegrityCheck;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableIntegrityCheck::new();
        verify_rule_descriptor(&rule, "AD2029", "EnableIntegrityCheck");
    }

    #[test]
    fn test_default_level() {
        let rule = EnableIntegrityCheck::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Error);
    }
}

mod ad2030_cast_guard_tests {
    use super::*;
    use aldur_rules::pe::EnableCastGuard;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableCastGuard::new();
        verify_rule_descriptor(&rule, "AD2030", "EnableCastGuard");
    }

    #[test]
    fn test_default_level() {
        let rule = EnableCastGuard::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad2031_control_stack_checking_tests {
    use super::*;
    use aldur_rules::pe::EnableControlStackChecking;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableControlStackChecking::new();
        verify_rule_descriptor(&rule, "AD2031", "EnableControlStackChecking");
    }

    #[test]
    fn test_default_level() {
        let rule = EnableControlStackChecking::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad2032_dotnet_high_entropy_tests {
    use super::*;
    use aldur_rules::pe::DotNetEnableHighEntropyVA;

    #[test]
    fn test_rule_descriptor() {
        let rule = DotNetEnableHighEntropyVA::new();
        verify_rule_descriptor(&rule, "AD2032", "DotNetEnableHighEntropyVA");
    }

    #[test]
    fn test_default_level() {
        let rule = DotNetEnableHighEntropyVA::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Error);
    }
}

mod ad2033_stack_protector_dwarf_tests {
    use super::*;
    use aldur_rules::pe::PeEnableStackProtectorDwarf;

    #[test]
    fn test_rule_descriptor() {
        let rule = PeEnableStackProtectorDwarf::new();
        verify_rule_descriptor(&rule, "AD2033", "PeEnableStackProtectorDwarf");
    }

    #[test]
    fn test_default_level() {
        let rule = PeEnableStackProtectorDwarf::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad2034_lto_dwarf_tests {
    use super::*;
    use aldur_rules::pe::PeEnableLtoDwarf;

    #[test]
    fn test_rule_descriptor() {
        let rule = PeEnableLtoDwarf::new();
        verify_rule_descriptor(&rule, "AD2034", "PeEnableLtoDwarf");
    }

    #[test]
    fn test_default_level() {
        let rule = PeEnableLtoDwarf::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Note);
    }
}

mod ad2035_compiler_data_dwarf_tests {
    use super::*;
    use aldur_rules::pe::PeReportCompilerDataDwarf;

    #[test]
    fn test_rule_descriptor() {
        let rule = PeReportCompilerDataDwarf::new();
        verify_rule_descriptor(&rule, "AD2035", "PeReportCompilerDataDwarf");
    }

    #[test]
    fn test_default_level() {
        let rule = PeReportCompilerDataDwarf::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Note);
    }
}

mod ad2036_pe_enable_cfi_tests {
    use super::*;
    use aldur_rules::pe::PeEnableControlFlowIntegrity;

    #[test]
    fn test_rule_descriptor() {
        let rule = PeEnableControlFlowIntegrity::new();
        verify_rule_descriptor(&rule, "AD2036", "PeEnableControlFlowIntegrity");
    }

    #[test]
    fn test_default_level() {
        let rule = PeEnableControlFlowIntegrity::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad2037_stack_clash_protection_tests {
    use super::*;
    use aldur_rules::pe::PeEnableStackClashProtection;

    #[test]
    fn test_rule_descriptor() {
        let rule = PeEnableStackClashProtection::new();
        verify_rule_descriptor(&rule, "AD2037", "PeEnableStackClashProtection");
    }

    #[test]
    fn test_default_level() {
        let rule = PeEnableStackClashProtection::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad2038_clang_safestack_tests {
    use super::*;
    use aldur_rules::pe::PeEnableClangSafeStack;

    #[test]
    fn test_rule_descriptor() {
        let rule = PeEnableClangSafeStack::new();
        verify_rule_descriptor(&rule, "AD2038", "PeEnableClangSafeStack");
    }

    #[test]
    fn test_default_level() {
        let rule = PeEnableClangSafeStack::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad2039_arm_pac_tests {
    use super::*;
    use aldur_rules::pe::PeEnableArmPAC;

    #[test]
    fn test_rule_descriptor() {
        let rule = PeEnableArmPAC::new();
        verify_rule_descriptor(&rule, "AD2039", "PeEnableArmPAC");
    }

    #[test]
    fn test_default_level() {
        let rule = PeEnableArmPAC::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad2040_arm_bti_tests {
    use super::*;
    use aldur_rules::pe::PeEnableArmBTI;

    #[test]
    fn test_rule_descriptor() {
        let rule = PeEnableArmBTI::new();
        verify_rule_descriptor(&rule, "AD2040", "PeEnableArmBTI");
    }

    #[test]
    fn test_default_level() {
        let rule = PeEnableArmBTI::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad2041_rust_sanitizers_tests {
    use super::*;
    use aldur_rules::pe::RustEnableSanitizersPE;

    #[test]
    fn test_rule_descriptor() {
        let rule = RustEnableSanitizersPE::new();
        verify_rule_descriptor(&rule, "AD2041", "RustEnableSanitizersPE");
    }

    #[test]
    fn test_default_level() {
        let rule = RustEnableSanitizersPE::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Note);
    }
}

mod ad2042_unicode_symbols_tests {
    use super::*;
    use aldur_rules::pe::NoUnicodeSymbolsPE;

    #[test]
    fn test_rule_descriptor() {
        let rule = NoUnicodeSymbolsPE::new();
        verify_rule_descriptor(&rule, "AD2042", "NoUnicodeSymbolsPE");
    }

    #[test]
    fn test_default_level() {
        let rule = NoUnicodeSymbolsPE::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad2043_banned_apis_tests {
    use super::*;
    use aldur_rules::pe::DoNotUseBannedApisPE;

    #[test]
    fn test_rule_descriptor() {
        let rule = DoNotUseBannedApisPE::new();
        verify_rule_descriptor(&rule, "AD2043", "DoNotUseBannedApisPE");
    }

    #[test]
    fn test_default_level() {
        let rule = DoNotUseBannedApisPE::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad2044_openssl_tests {
    use super::*;
    use aldur_rules::pe::DoNotStaticallyLinkOpenSSLPE;

    #[test]
    fn test_rule_descriptor() {
        let rule = DoNotStaticallyLinkOpenSSLPE::new();
        verify_rule_descriptor(&rule, "AD2044", "DoNotStaticallyLinkOpenSSLPE");
    }

    #[test]
    fn test_default_level() {
        let rule = DoNotStaticallyLinkOpenSSLPE::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad2045_ubsan_tests {
    use super::*;
    use aldur_rules::pe::EnableUBSanPE;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableUBSanPE::new();
        verify_rule_descriptor(&rule, "AD2045", "EnableUBSanPE");
    }

    #[test]
    fn test_default_level() {
        let rule = EnableUBSanPE::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Note);
    }
}

mod ad2046_address_sanitizer_tests {
    use super::*;
    use aldur_rules::pe::EnableAddressSanitizerPE;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableAddressSanitizerPE::new();
        verify_rule_descriptor(&rule, "AD2046", "EnableAddressSanitizerPE");
    }

    #[test]
    fn test_default_level() {
        let rule = EnableAddressSanitizerPE::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Note);
    }
}

mod ad2047_shadow_call_stack_tests {
    use super::*;
    use aldur_rules::pe::PeEnableShadowCallStack;

    #[test]
    fn test_rule_descriptor() {
        let rule = PeEnableShadowCallStack::new();
        verify_rule_descriptor(&rule, "AD2047", "PeEnableShadowCallStack");
    }

    #[test]
    fn test_default_level() {
        let rule = PeEnableShadowCallStack::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Note);
    }
}

mod ad2048_stack_variable_init_tests {
    use super::*;
    use aldur_rules::pe::PeEnableStackVariableInitialization;

    #[test]
    fn test_rule_descriptor() {
        let rule = PeEnableStackVariableInitialization::new();
        verify_rule_descriptor(&rule, "AD2048", "PeEnableStackVariableInitialization");
    }

    #[test]
    fn test_default_level() {
        let rule = PeEnableStackVariableInitialization::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Note);
    }
}

mod ad2050_custom_base_address_tests {
    use super::*;
    use aldur_rules::pe::DoNotUseCustomBaseAddress;

    #[test]
    fn test_rule_descriptor() {
        let rule = DoNotUseCustomBaseAddress::new();
        verify_rule_descriptor(&rule, "AD2050", "DoNotUseCustomBaseAddress");
    }

    #[test]
    fn test_default_level() {
        let rule = DoNotUseCustomBaseAddress::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad2051_minimum_library_versions_tests {
    use super::*;
    use aldur_rules::pe::CheckMinimumLibraryVersions;

    #[test]
    fn test_rule_descriptor() {
        let rule = CheckMinimumLibraryVersions::new();
        verify_rule_descriptor(&rule, "AD2051", "CheckMinimumLibraryVersions");
    }

    #[test]
    fn test_default_level() {
        let rule = CheckMinimumLibraryVersions::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Error);
    }
}

mod ad3034_rust_cfg_tests {
    use super::*;
    use aldur_rules::pe::RustEnableControlFlowGuard;

    #[test]
    fn test_rule_descriptor() {
        let rule = RustEnableControlFlowGuard::new();
        verify_rule_descriptor(&rule, "AD3034", "RustEnableControlFlowGuard");
    }

    #[test]
    fn test_default_level() {
        let rule = RustEnableControlFlowGuard::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad4001_compiler_data_tests {
    use super::*;
    use aldur_rules::pe::ReportPECompilerData;

    #[test]
    fn test_rule_descriptor() {
        let rule = ReportPECompilerData::new();
        verify_rule_descriptor(&rule, "AD4001", "ReportPECompilerData");
    }

    #[test]
    fn test_default_level() {
        let rule = ReportPECompilerData::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Note);
    }
}

mod ad6001_incremental_linking_tests {
    use super::*;
    use aldur_rules::pe::DisableIncrementalLinkingInReleaseBuilds;

    #[test]
    fn test_rule_descriptor() {
        let rule = DisableIncrementalLinkingInReleaseBuilds::new();
        verify_rule_descriptor(&rule, "AD6001", "DisableIncrementalLinkingInReleaseBuilds");
    }

    #[test]
    fn test_default_level() {
        let rule = DisableIncrementalLinkingInReleaseBuilds::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad6002_duplicate_strings_tests {
    use super::*;
    use aldur_rules::pe::EliminateDuplicateStrings;

    #[test]
    fn test_rule_descriptor() {
        let rule = EliminateDuplicateStrings::new();
        verify_rule_descriptor(&rule, "AD6002", "EliminateDuplicateStrings");
    }

    #[test]
    fn test_default_level() {
        let rule = EliminateDuplicateStrings::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad6004_comdat_folding_tests {
    use super::*;
    use aldur_rules::pe::EnableComdatFolding;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableComdatFolding::new();
        verify_rule_descriptor(&rule, "AD6004", "EnableComdatFolding");
    }

    #[test]
    fn test_default_level() {
        let rule = EnableComdatFolding::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad6005_optimize_references_tests {
    use super::*;
    use aldur_rules::pe::EnableOptimizeReferences;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableOptimizeReferences::new();
        verify_rule_descriptor(&rule, "AD6005", "EnableOptimizeReferences");
    }

    #[test]
    fn test_default_level() {
        let rule = EnableOptimizeReferences::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad6006_ltcg_tests {
    use super::*;
    use aldur_rules::pe::EnableLinkTimeCodeGeneration;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableLinkTimeCodeGeneration::new();
        verify_rule_descriptor(&rule, "AD6006", "EnableLinkTimeCodeGeneration");
    }

    #[test]
    fn test_default_level() {
        let rule = EnableLinkTimeCodeGeneration::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

// Test that all rules can be loaded without panicking
mod rule_loading_tests {
    use aldur_rules::pe;

    #[test]
    fn test_all_rules_instantiate() {
        let _ = pe::LoadImagesAboveFourGigabyteAddress::new();
        let _ = pe::EnableSecureSourceCodeHashing::new();
        let _ = pe::BuildWithSecureTools::new();
        let _ = pe::EnableCriticalCompilerWarnings::new();
        let _ = pe::EnableControlFlowGuard::new();
        let _ = pe::EnableAddressSpaceLayoutRandomization::new();
        let _ = pe::DoNotMarkImportsSectionAsExecutable::new();
        let _ = pe::EnableStackProtection::new();
        let _ = pe::DoNotModifyStackProtectionCookie::new();
        let _ = pe::InitializeStackProtection::new();
        let _ = pe::DoNotDisableStackProtectionForFunctions::new();
        let _ = pe::EnableHighEntropyVirtualAddresses::new();
        let _ = pe::MarkImageAsNXCompatible::new();
        let _ = pe::EnableSafeSEH::new();
        let _ = pe::DoNotMarkWritableSectionsAsShared::new();
        let _ = pe::DoNotMarkWritableSectionsAsExecutable::new();
        let _ = pe::EnableSpectreMitigations::new();
        let _ = pe::EnableShadowStack::new();
        let _ = pe::EnableMicrosoftCompilerSdlSwitch::new();
        let _ = pe::EnableSourceLink::new();
        let _ = pe::EnableIntegrityCheck::new();
        let _ = pe::EnableCastGuard::new();
        let _ = pe::EnableControlStackChecking::new();
        let _ = pe::DotNetEnableHighEntropyVA::new();
        let _ = pe::PeEnableStackProtectorDwarf::new();
        let _ = pe::PeEnableLtoDwarf::new();
        let _ = pe::PeReportCompilerDataDwarf::new();
        let _ = pe::PeEnableControlFlowIntegrity::new();
        let _ = pe::PeEnableStackClashProtection::new();
        let _ = pe::PeEnableClangSafeStack::new();
        let _ = pe::PeEnableArmPAC::new();
        let _ = pe::PeEnableArmBTI::new();
        let _ = pe::RustEnableControlFlowGuard::new();
        let _ = pe::RustEnableSanitizersPE::new();
        let _ = pe::NoUnicodeSymbolsPE::new();
        let _ = pe::DoNotUseBannedApisPE::new();
        let _ = pe::DoNotStaticallyLinkOpenSSLPE::new();
        let _ = pe::EnableUBSanPE::new();
        let _ = pe::EnableAddressSanitizerPE::new();
        let _ = pe::PeEnableShadowCallStack::new();
        let _ = pe::PeEnableStackVariableInitialization::new();
        let _ = pe::ReportPECompilerData::new();
        let _ = pe::DisableIncrementalLinkingInReleaseBuilds::new();
        let _ = pe::EliminateDuplicateStrings::new();
        let _ = pe::EnableComdatFolding::new();
        let _ = pe::EnableOptimizeReferences::new();
        let _ = pe::EnableLinkTimeCodeGeneration::new();
        let _ = pe::DoNotUseCustomBaseAddress::new();
        let _ = pe::CheckMinimumLibraryVersions::new();
        let _ = pe::RequireAuthenticode::new();
        let _ = pe::AllowIsolation::new();
        let _ = pe::EnableReturnFlowGuard::new();
    }

    #[test]
    fn test_all_rules_returns_expected_count() {
        let rules = pe::all_rules();
        // 50 PE rules total
        assert!(rules.len() >= 48, "Expected at least 48 PE rules, got {}", rules.len());
    }

    #[test]
    fn test_all_rules_unique_ids() {
        let rules = pe::all_rules();
        let mut ids: Vec<_> = rules.iter().map(|r| r.descriptor().id.clone()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), rules.len(), "All rule IDs should be unique");
    }

    #[test]
    fn test_all_rules_have_ad_ids() {
        let rules = pe::all_rules();
        for rule in &rules {
            let id = &rule.descriptor().id;
            assert!(id.starts_with("AD"), "PE rules should have AD IDs, got {}", id);
        }
    }
}

// ============================================================================
// INTEGRATION TESTS - Testing rules against actual PE binaries
// ============================================================================

mod pe_integration_tests {
    use super::*;
    use aldur_rules::pe;

    /// Check if PE fixtures exist
    fn fixtures_available() -> bool {
        pe_fixtures_dir().join("hardened.exe").exists()
    }

    mod aslr_tests {
        use super::*;

        #[test]
        fn test_hardened_binary_has_aslr() {
            if !fixtures_available() {
                eprintln!("Skipping: PE fixtures not available");
                return;
            }

            let rule = pe::EnableAddressSpaceLayoutRandomization::new();
            if let Some((applicability, results)) = run_pe_rule(&rule, "hardened.exe") {
                assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
                assert!(!results.is_empty(), "Expected results from ASLR check");
                assert!(results.iter().any(|r| r.kind == ResultKind::Pass),
                    "Hardened binary should pass ASLR check");
            }
        }

        #[test]
        fn test_no_aslr_binary_fails() {
            if !fixtures_available() {
                eprintln!("Skipping: PE fixtures not available");
                return;
            }

            let rule = pe::EnableAddressSpaceLayoutRandomization::new();
            if let Some((applicability, results)) = run_pe_rule(&rule, "no_aslr.exe") {
                assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
                assert!(!results.is_empty(), "Expected results from ASLR check");
                assert!(results.iter().any(|r| r.kind == ResultKind::Fail),
                    "No-ASLR binary should fail ASLR check");
            }
        }
    }

    mod high_entropy_va_tests {
        use super::*;

        #[test]
        fn test_hardened_binary_has_high_entropy_va() {
            if !fixtures_available() {
                eprintln!("Skipping: PE fixtures not available");
                return;
            }

            let rule = pe::EnableHighEntropyVirtualAddresses::new();
            if let Some((applicability, results)) = run_pe_rule(&rule, "hardened.exe") {
                assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
                assert!(!results.is_empty(), "Expected results from high entropy VA check");
                assert!(results.iter().any(|r| r.kind == ResultKind::Pass),
                    "Hardened binary should pass high entropy VA check");
            }
        }

        #[test]
        fn test_no_high_entropy_binary_fails() {
            if !fixtures_available() {
                eprintln!("Skipping: PE fixtures not available");
                return;
            }

            let rule = pe::EnableHighEntropyVirtualAddresses::new();
            if let Some((applicability, results)) = run_pe_rule(&rule, "no_high_entropy.exe") {
                assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
                assert!(!results.is_empty(), "Expected results from high entropy VA check");
                assert!(results.iter().any(|r| r.kind == ResultKind::Fail),
                    "No-high-entropy binary should fail the check");
            }
        }
    }

    mod nx_tests {
        use super::*;

        #[test]
        fn test_hardened_binary_is_nx_compatible() {
            if !fixtures_available() {
                eprintln!("Skipping: PE fixtures not available");
                return;
            }

            let rule = pe::MarkImageAsNXCompatible::new();
            if let Some((applicability, results)) = run_pe_rule(&rule, "hardened.exe") {
                assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
                assert!(!results.is_empty(), "Expected results from NX check");
                assert!(results.iter().any(|r| r.kind == ResultKind::Pass),
                    "Hardened binary should pass NX compatibility check");
            }
        }

        #[test]
        fn test_no_nx_binary_fails() {
            if !fixtures_available() {
                eprintln!("Skipping: PE fixtures not available");
                return;
            }

            let rule = pe::MarkImageAsNXCompatible::new();
            if let Some((applicability, results)) = run_pe_rule(&rule, "no_nx.exe") {
                assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
                assert!(!results.is_empty(), "Expected results from NX check");
                assert!(results.iter().any(|r| r.kind == ResultKind::Fail),
                    "No-NX binary should fail NX compatibility check");
            }
        }
    }

    mod dll_tests {
        use super::*;

        #[test]
        fn test_dll_can_be_analyzed() {
            if !fixtures_available() {
                eprintln!("Skipping: PE fixtures not available");
                return;
            }

            let rule = pe::EnableAddressSpaceLayoutRandomization::new();
            if let Some((applicability, results)) = run_pe_rule(&rule, "test_lib.dll") {
                assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
                assert!(!results.is_empty(), "Expected results from DLL analysis");
                assert!(results.iter().any(|r| r.kind == ResultKind::Pass),
                    "DLL should pass ASLR check");
            }
        }

        #[test]
        fn test_dll_has_high_entropy_va() {
            if !fixtures_available() {
                eprintln!("Skipping: PE fixtures not available");
                return;
            }

            let rule = pe::EnableHighEntropyVirtualAddresses::new();
            if let Some((applicability, results)) = run_pe_rule(&rule, "test_lib.dll") {
                assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
                assert!(!results.is_empty(), "Expected results from DLL analysis");
            }
        }
    }

    mod section_tests {
        use super::*;

        #[test]
        fn test_hardened_binary_sections() {
            if !fixtures_available() {
                eprintln!("Skipping: PE fixtures not available");
                return;
            }

            let rule = pe::DoNotMarkWritableSectionsAsExecutable::new();
            if let Some((applicability, results)) = run_pe_rule(&rule, "hardened.exe") {
                assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
                assert!(!results.is_empty(), "Expected results from section check");
                // Hardened binary should not have writable+executable sections
                assert!(results.iter().any(|r| r.kind == ResultKind::Pass),
                    "Hardened binary should pass WX section check");
            }
        }
    }

    mod multi_rule_tests {
        use super::*;

        #[test]
        fn test_all_rules_can_analyze_hardened_binary() {
            if !fixtures_available() {
                eprintln!("Skipping: PE fixtures not available");
                return;
            }

            let rules = pe::all_rules();
            let mut applicable_count = 0;

            for rule in &rules {
                if let Some((applicability, _)) = run_pe_rule(rule.as_ref(), "hardened.exe") {
                    if applicability == AnalysisApplicability::ApplicableToSpecifiedTarget {
                        applicable_count += 1;
                    }
                }
            }

            // At least some rules should be applicable to a PE binary
            assert!(applicable_count > 5,
                "Expected at least 5 rules to be applicable, got {}", applicable_count);
        }

        #[test]
        fn test_console_vs_gui_app() {
            if !fixtures_available() {
                eprintln!("Skipping: PE fixtures not available");
                return;
            }

            // Both console and GUI apps should be analyzable
            let rule = pe::EnableAddressSpaceLayoutRandomization::new();

            if let Some((app_console, _)) = run_pe_rule(&rule, "console_app.exe") {
                assert_eq!(app_console, AnalysisApplicability::ApplicableToSpecifiedTarget);
            }

            if let Some((app_gui, _)) = run_pe_rule(&rule, "gui_app.exe") {
                assert_eq!(app_gui, AnalysisApplicability::ApplicableToSpecifiedTarget);
            }
        }
    }
}

