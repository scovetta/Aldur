//! Integration tests for Mach-O security rules
//!
//! Note: Full integration tests require Mach-O binaries compiled on macOS.
//! These tests focus on rule descriptor validation and logic verification.

use aldur_core::{FailureLevel, Rule};

/// Verify rule descriptor is properly configured
fn verify_rule_descriptor(rule: &dyn Rule, expected_id: &str, expected_name: &str) {
    let desc = rule.descriptor();
    assert_eq!(desc.id, expected_id, "Rule ID mismatch");
    assert_eq!(desc.name, expected_name, "Rule name mismatch");
    assert!(!desc.short_description.is_empty(), "Short description should not be empty");
    assert!(!desc.full_description.is_empty(), "Full description should not be empty");
}

mod ad5001_pie_tests {
    use super::*;
    use aldur_rules::macho::EnablePositionIndependentExecutableMachO;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnablePositionIndependentExecutableMachO::new();
        verify_rule_descriptor(&rule, "AD5001", "EnablePositionIndependentExecutableMachO");
    }

    #[test]
    fn test_default_level() {
        let rule = EnablePositionIndependentExecutableMachO::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Error);
    }
}

mod ad5002_executable_stack_tests {
    use super::*;
    use aldur_rules::macho::DoNotAllowExecutableStack;

    #[test]
    fn test_rule_descriptor() {
        let rule = DoNotAllowExecutableStack::new();
        verify_rule_descriptor(&rule, "AD5002", "DoNotAllowExecutableStack");
    }

    #[test]
    fn test_default_level() {
        let rule = DoNotAllowExecutableStack::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Error);
    }
}

mod ad5003_stack_protector_tests {
    use super::*;
    use aldur_rules::macho::EnableStackProtectorMachO;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableStackProtectorMachO::new();
        verify_rule_descriptor(&rule, "AD5003", "EnableStackProtectorMachO");
    }

    #[test]
    fn test_default_level() {
        let rule = EnableStackProtectorMachO::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Error);
    }

    #[test]
    fn test_has_messages() {
        let rule = EnableStackProtectorMachO::new();
        let desc = rule.descriptor();
        assert!(desc.messages.contains_key("Pass"), "Should have Pass message");
        assert!(desc.messages.contains_key("Error"), "Should have Error message");
    }
}

mod ad5004_fortify_tests {
    use super::*;
    use aldur_rules::macho::UseFortifiedFunctionsMachO;

    #[test]
    fn test_rule_descriptor() {
        let rule = UseFortifiedFunctionsMachO::new();
        verify_rule_descriptor(&rule, "AD5004", "UseFortifiedFunctionsMachO");
    }

    #[test]
    fn test_default_level() {
        let rule = UseFortifiedFunctionsMachO::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad5005_executable_heap_tests {
    use super::*;
    use aldur_rules::macho::DoNotAllowExecutableHeap;

    #[test]
    fn test_rule_descriptor() {
        let rule = DoNotAllowExecutableHeap::new();
        verify_rule_descriptor(&rule, "AD5005", "DoNotAllowExecutableHeap");
    }

    #[test]
    fn test_default_level() {
        let rule = DoNotAllowExecutableHeap::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad5006_two_level_namespace_tests {
    use super::*;
    use aldur_rules::macho::UseTwoLevelNamespace;

    #[test]
    fn test_rule_descriptor() {
        let rule = UseTwoLevelNamespace::new();
        verify_rule_descriptor(&rule, "AD5006", "UseTwoLevelNamespace");
    }

    #[test]
    fn test_default_level() {
        let rule = UseTwoLevelNamespace::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad5007_arm_pac_tests {
    use super::*;
    use aldur_rules::macho::EnableArmPACMachO;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableArmPACMachO::new();
        verify_rule_descriptor(&rule, "AD5007", "EnableArmPACMachO");
    }

    #[test]
    fn test_default_level() {
        let rule = EnableArmPACMachO::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad5008_safestack_tests {
    use super::*;
    use aldur_rules::macho::EnableClangSafeStackMachO;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableClangSafeStackMachO::new();
        verify_rule_descriptor(&rule, "AD5008", "EnableClangSafeStackMachO");
    }

    #[test]
    fn test_default_level() {
        let rule = EnableClangSafeStackMachO::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad5009_weak_dylib_tests {
    use super::*;
    use aldur_rules::macho::DoNotUseWeakDylib;

    #[test]
    fn test_rule_descriptor() {
        let rule = DoNotUseWeakDylib::new();
        verify_rule_descriptor(&rule, "AD5009", "DoNotUseWeakDylib");
    }

    #[test]
    fn test_default_level() {
        let rule = DoNotUseWeakDylib::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad5010_arc_tests {
    use super::*;
    use aldur_rules::macho::EnableAutomaticReferenceCounting;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableAutomaticReferenceCounting::new();
        verify_rule_descriptor(&rule, "AD5010", "EnableAutomaticReferenceCounting");
    }

    #[test]
    fn test_default_level() {
        let rule = EnableAutomaticReferenceCounting::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad5011_code_signature_tests {
    use super::*;
    use aldur_rules::macho::RequireCodeSignature;

    #[test]
    fn test_rule_descriptor() {
        let rule = RequireCodeSignature::new();
        verify_rule_descriptor(&rule, "AD5011", "RequireCodeSignature");
    }

    #[test]
    fn test_default_level() {
        let rule = RequireCodeSignature::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad5012_segment_permissions_tests {
    use super::*;
    use aldur_rules::macho::ValidateSegmentPermissions;

    #[test]
    fn test_rule_descriptor() {
        let rule = ValidateSegmentPermissions::new();
        verify_rule_descriptor(&rule, "AD5012", "ValidateSegmentPermissions");
    }

    #[test]
    fn test_default_level() {
        let rule = ValidateSegmentPermissions::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Error);
    }

    #[test]
    fn test_has_messages() {
        let rule = ValidateSegmentPermissions::new();
        let desc = rule.descriptor();
        assert!(desc.messages.contains_key("Pass"), "Should have Pass message");
        assert!(desc.messages.contains_key("Error_WritableText"), "Should have Error_WritableText message");
        assert!(desc.messages.contains_key("Error_ExecutableData"), "Should have Error_ExecutableData message");
        assert!(desc.messages.contains_key("Error_WXViolation"), "Should have Error_WXViolation message");
    }
}

mod ad5013_banned_apis_tests {
    use super::*;
    use aldur_rules::macho::DoNotUseBannedApisMachO;

    #[test]
    fn test_rule_descriptor() {
        let rule = DoNotUseBannedApisMachO::new();
        verify_rule_descriptor(&rule, "AD5013", "DoNotUseBannedApisMachO");
    }

    #[test]
    fn test_default_level() {
        let rule = DoNotUseBannedApisMachO::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }

    #[test]
    fn test_has_messages() {
        let rule = DoNotUseBannedApisMachO::new();
        let desc = rule.descriptor();
        assert!(desc.messages.contains_key("Pass"), "Should have Pass message");
        assert!(desc.messages.contains_key("Warning"), "Should have Warning message");
        assert!(desc.messages.contains_key("Error_Critical"), "Should have Error_Critical message");
    }
}

mod ad5014_address_sanitizer_tests {
    use super::*;
    use aldur_rules::macho::UseAddressSanitizer;

    #[test]
    fn test_rule_descriptor() {
        let rule = UseAddressSanitizer::new();
        verify_rule_descriptor(&rule, "AD5014", "UseAddressSanitizer");
    }

    #[test]
    fn test_default_level() {
        let rule = UseAddressSanitizer::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Note);
    }
}

mod ad5015_openssl_tests {
    use super::*;
    use aldur_rules::macho::DoNotStaticallyLinkOpenSSL;

    #[test]
    fn test_rule_descriptor() {
        let rule = DoNotStaticallyLinkOpenSSL::new();
        verify_rule_descriptor(&rule, "AD5015", "DoNotStaticallyLinkOpenSSL");
    }

    #[test]
    fn test_default_level() {
        let rule = DoNotStaticallyLinkOpenSSL::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad5016_unicode_symbols_tests {
    use super::*;
    use aldur_rules::macho::NoUnicodeSymbolsMachO;

    #[test]
    fn test_rule_descriptor() {
        let rule = NoUnicodeSymbolsMachO::new();
        verify_rule_descriptor(&rule, "AD5016", "NoUnicodeSymbolsMachO");
    }

    #[test]
    fn test_default_level() {
        let rule = NoUnicodeSymbolsMachO::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad5017_lto_tests {
    use super::*;
    use aldur_rules::macho::EnableLTOMachO;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableLTOMachO::new();
        verify_rule_descriptor(&rule, "AD5017", "EnableLTOMachO");
    }

    #[test]
    fn test_default_level() {
        let rule = EnableLTOMachO::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Note);
    }
}

mod ad5018_min_os_version_tests {
    use super::*;
    use aldur_rules::macho::RequireMinimumOSVersion;

    #[test]
    fn test_rule_descriptor() {
        let rule = RequireMinimumOSVersion::new();
        verify_rule_descriptor(&rule, "AD5018", "RequireMinimumOSVersion");
    }

    #[test]
    fn test_default_level() {
        let rule = RequireMinimumOSVersion::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad5019_restrict_segment_tests {
    use super::*;
    use aldur_rules::macho::UseRestrictSegment;

    #[test]
    fn test_rule_descriptor() {
        let rule = UseRestrictSegment::new();
        verify_rule_descriptor(&rule, "AD5019", "UseRestrictSegment");
    }

    #[test]
    fn test_default_level() {
        let rule = UseRestrictSegment::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Note);
    }
}

mod ad5020_rust_sanitizers_tests {
    use super::*;
    use aldur_rules::macho::RustEnableSanitizersMachO;

    #[test]
    fn test_rule_descriptor() {
        let rule = RustEnableSanitizersMachO::new();
        verify_rule_descriptor(&rule, "AD5020", "RustEnableSanitizersMachO");
    }

    #[test]
    fn test_default_level() {
        let rule = RustEnableSanitizersMachO::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Note);
    }
}

mod ad5021_rust_secure_hash_tests {
    use super::*;
    use aldur_rules::macho::RustEnableSecureSourceHashMachO;

    #[test]
    fn test_rule_descriptor() {
        let rule = RustEnableSecureSourceHashMachO::new();
        verify_rule_descriptor(&rule, "AD5021", "RustEnableSecureSourceHashMachO");
    }

    #[test]
    fn test_default_level() {
        let rule = RustEnableSecureSourceHashMachO::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad5022_rust_lto_tests {
    use super::*;
    use aldur_rules::macho::RustMachOEnableLTO;

    #[test]
    fn test_rule_descriptor() {
        let rule = RustMachOEnableLTO::new();
        verify_rule_descriptor(&rule, "AD5022", "RustMachOEnableLTO");
    }

    #[test]
    fn test_default_level() {
        let rule = RustMachOEnableLTO::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Note);
    }
}

mod ad5023_ubsan_tests {
    use super::*;
    use aldur_rules::macho::EnableUBSanMachO;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableUBSanMachO::new();
        verify_rule_descriptor(&rule, "AD5023", "EnableUBSanMachO");
    }

    #[test]
    fn test_default_level() {
        let rule = EnableUBSanMachO::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Note);
    }
}

mod ad5024_stack_clash_protection_tests {
    use super::*;
    use aldur_rules::macho::EnableStackClashProtectionMachO;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableStackClashProtectionMachO::new();
        verify_rule_descriptor(&rule, "AD5024", "EnableStackClashProtectionMachO");
    }

    #[test]
    fn test_default_level() {
        let rule = EnableStackClashProtectionMachO::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Note);
    }
}

mod ad5025_cfi_tests {
    use super::*;
    use aldur_rules::macho::EnableControlFlowIntegrityMachO;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableControlFlowIntegrityMachO::new();
        verify_rule_descriptor(&rule, "AD5025", "EnableControlFlowIntegrityMachO");
    }

    #[test]
    fn test_default_level() {
        let rule = EnableControlFlowIntegrityMachO::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Note);
    }
}

mod ad5026_arm_bti_tests {
    use super::*;
    use aldur_rules::macho::EnableArmBTIMachO;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableArmBTIMachO::new();
        verify_rule_descriptor(&rule, "AD5026", "EnableArmBTIMachO");
    }

    #[test]
    fn test_default_level() {
        let rule = EnableArmBTIMachO::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Note);
    }
}

mod ad5027_slh_tests {
    use super::*;
    use aldur_rules::macho::EnableSpeculativeLoadHardeningMachO;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableSpeculativeLoadHardeningMachO::new();
        verify_rule_descriptor(&rule, "AD5027", "EnableSpeculativeLoadHardeningMachO");
    }

    #[test]
    fn test_default_level() {
        let rule = EnableSpeculativeLoadHardeningMachO::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Note);
    }
}

mod ad5028_optimization_tests {
    use super::*;
    use aldur_rules::macho::EnableOptimizationMachO;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableOptimizationMachO::new();
        verify_rule_descriptor(&rule, "AD5028", "EnableOptimizationMachO");
    }

    #[test]
    fn test_default_level() {
        let rule = EnableOptimizationMachO::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod ad5029_arm_mte_tests {
    use super::*;
    use aldur_rules::macho::EnableArmMTEMachO;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableArmMTEMachO::new();
        verify_rule_descriptor(&rule, "AD5029", "EnableArmMTEMachO");
    }

    #[test]
    fn test_default_level() {
        let rule = EnableArmMTEMachO::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Note);
    }
}

mod ad5030_exception_handling_tests {
    use super::*;
    use aldur_rules::macho::EnableExceptionHandlingMachO;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableExceptionHandlingMachO::new();
        verify_rule_descriptor(&rule, "AD5030", "EnableExceptionHandlingMachO");
    }

    #[test]
    fn test_default_level() {
        let rule = EnableExceptionHandlingMachO::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Note);
    }
}

mod ad5031_check_not_encrypted_tests {
    use super::*;
    use aldur_rules::macho::CheckNotEncrypted;

    #[test]
    fn test_rule_descriptor() {
        let rule = CheckNotEncrypted::new();
        verify_rule_descriptor(&rule, "AD5031", "CheckNotEncrypted");
    }

    #[test]
    fn test_default_level() {
        let rule = CheckNotEncrypted::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Note);
    }
}

mod ad5040_unchecked_optimization_tests {
    use super::*;
    use aldur_rules::macho::DoNotUseUncheckedOptimization;

    #[test]
    fn test_rule_descriptor() {
        let rule = DoNotUseUncheckedOptimization::new();
        verify_rule_descriptor(&rule, "AD5040", "DoNotUseUncheckedOptimization");
    }

    #[test]
    fn test_default_level() {
        let rule = DoNotUseUncheckedOptimization::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}

mod all_rules_tests {
    use aldur_rules::macho::all_rules;
    use aldur_rules::macho;

    #[test]
    fn test_all_rules_count() {
        let rules = all_rules();
        assert_eq!(rules.len(), 32, "Expected 32 Mach-O rules");
    }

    #[test]
    fn test_all_rules_unique_ids() {
        let rules = all_rules();
        let mut ids: Vec<_> = rules.iter().map(|r| r.descriptor().id.clone()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), rules.len(), "All rule IDs should be unique");
    }

    #[test]
    fn test_all_rules_ad50xx_ids() {
        let rules = all_rules();
        for rule in &rules {
            let id = &rule.descriptor().id;
            assert!(id.starts_with("AD50"), "Mach-O rules should have AD50xx IDs, got {}", id);
        }
    }

    #[test]
    fn test_all_rules_instantiate() {
        let _ = macho::EnablePositionIndependentExecutableMachO::new();
        let _ = macho::DoNotAllowExecutableStack::new();
        let _ = macho::EnableStackProtectorMachO::new();
        let _ = macho::UseFortifiedFunctionsMachO::new();
        let _ = macho::DoNotAllowExecutableHeap::new();
        let _ = macho::UseTwoLevelNamespace::new();
        let _ = macho::EnableArmPACMachO::new();
        let _ = macho::EnableClangSafeStackMachO::new();
        let _ = macho::DoNotUseWeakDylib::new();
        let _ = macho::EnableAutomaticReferenceCounting::new();
        let _ = macho::RequireCodeSignature::new();
        let _ = macho::ValidateSegmentPermissions::new();
        let _ = macho::DoNotUseBannedApisMachO::new();
        let _ = macho::UseAddressSanitizer::new();
        let _ = macho::DoNotStaticallyLinkOpenSSL::new();
        let _ = macho::NoUnicodeSymbolsMachO::new();
        let _ = macho::EnableLTOMachO::new();
        let _ = macho::RequireMinimumOSVersion::new();
        let _ = macho::UseRestrictSegment::new();
        let _ = macho::RustEnableSanitizersMachO::new();
        let _ = macho::RustEnableSecureSourceHashMachO::new();
        let _ = macho::RustMachOEnableLTO::new();
        let _ = macho::EnableUBSanMachO::new();
        let _ = macho::EnableStackClashProtectionMachO::new();
        let _ = macho::EnableControlFlowIntegrityMachO::new();
        let _ = macho::EnableArmBTIMachO::new();
        let _ = macho::EnableSpeculativeLoadHardeningMachO::new();
        let _ = macho::EnableOptimizationMachO::new();
        let _ = macho::EnableArmMTEMachO::new();
        let _ = macho::EnableExceptionHandlingMachO::new();
        let _ = macho::CheckNotEncrypted::new();
        let _ = macho::DoNotUseUncheckedOptimization::new();
    }
}
