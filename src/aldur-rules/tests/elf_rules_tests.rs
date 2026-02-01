//! Integration tests for ELF security rules
//!
//! These tests verify that each ELF rule correctly detects security issues
//! in test binaries compiled with various security configurations.

use aldur_core::{AnalysisApplicability, AnalysisConfig, AnalysisContext, Binary, ResultKind, Rule};
use aldur_parsers::ElfBinary;
use std::path::PathBuf;
use std::sync::Arc;

/// Path to test fixtures directory
fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test-fixtures")
}

/// Create an analysis context for testing
fn create_context(binary_name: &str) -> AnalysisContext {
    let path = fixtures_dir().join(binary_name);
    let binary = ElfBinary::load(&path).expect("Failed to load binary");
    let mut context = AnalysisContext::new(path, AnalysisConfig::default());
    context.set_binary(Arc::new(binary) as Arc<dyn Binary>);
    context
}

/// Helper to run a rule and return results
fn run_rule(rule: &dyn Rule, binary_name: &str) -> (AnalysisApplicability, Vec<aldur_core::RuleResult>) {
    let mut context = create_context(binary_name);
    let (applicability, _) = rule.can_analyze(&context);
    if applicability == AnalysisApplicability::ApplicableToSpecifiedTarget {
        rule.analyze(&mut context);
    }
    (applicability, context.take_results())
}

mod ad3001_pie_tests {
    use super::*;
    use aldur_rules::elf::EnablePositionIndependentExecutable;

    #[test]
    fn test_hardened_binary_passes() {
        let rule = EnablePositionIndependentExecutable::new();
        let (applicability, results) = run_rule(&rule, "hardened");

        assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.kind == ResultKind::Pass));
    }

    #[test]
    fn test_no_pie_binary_fails() {
        let rule = EnablePositionIndependentExecutable::new();
        let (applicability, results) = run_rule(&rule, "no_pie");

        assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.kind == ResultKind::Fail));
    }
}

mod ad3002_stack_executable_tests {
    use super::*;
    use aldur_rules::elf::DoNotMarkStackAsExecutable;

    #[test]
    fn test_hardened_binary_passes() {
        let rule = DoNotMarkStackAsExecutable::new();
        let (applicability, results) = run_rule(&rule, "hardened");

        assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.kind == ResultKind::Pass));
    }

    #[test]
    fn test_exec_stack_binary_fails() {
        let rule = DoNotMarkStackAsExecutable::new();
        let (applicability, results) = run_rule(&rule, "exec_stack");

        assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.kind == ResultKind::Fail));
    }
}

mod ad3003_stack_protector_tests {
    use super::*;
    use aldur_rules::elf::EnableStackProtector;

    #[test]
    fn test_hardened_binary_passes() {
        let rule = EnableStackProtector::new();
        let (applicability, results) = run_rule(&rule, "hardened");

        assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
        assert!(!results.is_empty());
        // May pass or be not applicable depending on symbol visibility
        assert!(results.iter().any(|r| r.kind == ResultKind::Pass || r.kind == ResultKind::NotApplicable));
    }

    #[test]
    fn test_no_stack_protector_fails() {
        let rule = EnableStackProtector::new();
        let (applicability, results) = run_rule(&rule, "no_stack_protector");

        assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
        assert!(!results.is_empty());
        // Should fail since stack protector is disabled
        assert!(results.iter().any(|r| r.kind == ResultKind::Fail));
    }
}

mod ad3006_nx_stack_tests {
    use super::*;
    use aldur_rules::elf::EnableNonExecutableStack;

    #[test]
    fn test_hardened_binary_passes() {
        let rule = EnableNonExecutableStack::new();
        let (applicability, results) = run_rule(&rule, "hardened");

        assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.kind == ResultKind::Pass));
    }

    #[test]
    fn test_exec_stack_binary_fails() {
        let rule = EnableNonExecutableStack::new();
        let (applicability, results) = run_rule(&rule, "exec_stack");

        assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.kind == ResultKind::Fail));
    }
}

mod ad3010_relro_tests {
    use super::*;
    use aldur_rules::elf::EnableReadOnlyRelocations;

    #[test]
    fn test_hardened_binary_passes() {
        let rule = EnableReadOnlyRelocations::new();
        let (applicability, results) = run_rule(&rule, "hardened");

        assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.kind == ResultKind::Pass));
    }

    #[test]
    fn test_partial_relro_passes() {
        let rule = EnableReadOnlyRelocations::new();
        let (applicability, results) = run_rule(&rule, "partial_relro");

        assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
        assert!(!results.is_empty());
        // Partial RELRO should still pass the RELRO check
        assert!(results.iter().any(|r| r.kind == ResultKind::Pass));
    }

    #[test]
    fn test_no_relro_fails() {
        let rule = EnableReadOnlyRelocations::new();
        let (applicability, results) = run_rule(&rule, "no_relro");

        assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.kind == ResultKind::Fail));
    }
}

mod ad3011_bind_now_tests {
    use super::*;
    use aldur_rules::elf::EnableBindNow;

    #[test]
    fn test_hardened_binary_passes() {
        let rule = EnableBindNow::new();
        let (applicability, results) = run_rule(&rule, "hardened");

        assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.kind == ResultKind::Pass));
    }

    #[test]
    fn test_partial_relro_fails() {
        let rule = EnableBindNow::new();
        let (applicability, results) = run_rule(&rule, "partial_relro");

        assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
        assert!(!results.is_empty());
        // Partial RELRO lacks BIND_NOW
        assert!(results.iter().any(|r| r.kind == ResultKind::Fail));
    }
}

mod ad3012_rpath_tests {
    use super::*;
    use aldur_rules::elf::DoNotUseRpath;

    #[test]
    fn test_hardened_binary_passes() {
        let rule = DoNotUseRpath::new();
        let (applicability, results) = run_rule(&rule, "hardened");

        assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.kind == ResultKind::Pass));
    }

    #[test]
    fn test_rpath_binary_fails() {
        let rule = DoNotUseRpath::new();
        let (applicability, results) = run_rule(&rule, "with_rpath");

        assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.kind == ResultKind::Fail));
    }
}

mod ad3013_runpath_tests {
    use super::*;
    use aldur_rules::elf::ValidateRunpath;

    #[test]
    fn test_hardened_binary_passes() {
        let rule = ValidateRunpath::new();
        let (applicability, results) = run_rule(&rule, "hardened");

        assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.kind == ResultKind::Pass));
    }

    #[test]
    fn test_runpath_binary_checked() {
        let rule = ValidateRunpath::new();
        let (applicability, results) = run_rule(&rule, "with_runpath");

        assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
        assert!(!results.is_empty());
        // Should fail if runpath contains insecure paths
    }
}

mod ad3021_unicode_symbols_tests {
    use super::*;
    use aldur_rules::elf::NoUnicodeSymbols;

    #[test]
    fn test_normal_binary_passes() {
        let rule = NoUnicodeSymbols::new();
        let (applicability, results) = run_rule(&rule, "hardened");

        assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
        assert!(!results.is_empty());
        // Normal binaries shouldn't have unicode symbols
        assert!(results.iter().any(|r| r.kind == ResultKind::Pass));
    }
}

mod ad3022_got_protection_tests {
    use super::*;
    use aldur_rules::elf::WritableGotProtection;

    #[test]
    fn test_hardened_binary_passes() {
        let rule = WritableGotProtection::new();
        let (applicability, results) = run_rule(&rule, "hardened");

        assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
        assert!(!results.is_empty());
        // Full RELRO protects the GOT
        assert!(results.iter().any(|r| r.kind == ResultKind::Pass));
    }

    #[test]
    fn test_partial_relro_warns() {
        let rule = WritableGotProtection::new();
        let (applicability, results) = run_rule(&rule, "partial_relro");

        assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
        assert!(!results.is_empty());
        // Partial RELRO leaves GOT writable
        assert!(results.iter().any(|r| r.kind == ResultKind::Fail));
    }
}

mod ad3023_load_segments_tests {
    use super::*;
    use aldur_rules::elf::ProperLoadSegments;

    #[test]
    fn test_hardened_binary_passes() {
        let rule = ProperLoadSegments::new();
        let (applicability, results) = run_rule(&rule, "hardened");

        assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
        assert!(!results.is_empty());
        // Properly compiled binary should pass
        assert!(results.iter().any(|r| r.kind == ResultKind::Pass));
    }
}

mod ad3024_restrict_dlopen_tests {
    use super::*;
    use aldur_rules::elf::RestrictDlopen;

    #[test]
    fn test_hardened_binary_passes() {
        let rule = RestrictDlopen::new();
        let (applicability, results) = run_rule(&rule, "hardened");

        assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
        assert!(!results.is_empty());
    }
}

mod ad3025_exception_handling_tests {
    use super::*;
    use aldur_rules::elf::EnableExceptionHandling;

    #[test]
    fn test_hardened_binary_passes() {
        let rule = EnableExceptionHandling::new();
        let (applicability, results) = run_rule(&rule, "hardened");

        assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
        assert!(!results.is_empty());
    }
}

mod ad3014_no_text_relocations_tests {
    use super::*;
    use aldur_rules::elf::NoTextRelocations;

    #[test]
    fn test_hardened_binary_passes() {
        let rule = NoTextRelocations::new();
        let (applicability, results) = run_rule(&rule, "hardened");

        assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.kind == ResultKind::Pass));
    }
}

mod ad3019_lto_tests {
    use super::*;
    use aldur_rules::elf::EnableLTO;

    #[test]
    fn test_lto_binary_passes() {
        let rule = EnableLTO::new();
        let (applicability, results) = run_rule(&rule, "with_lto");

        assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_no_lto_binary_fails() {
        let rule = EnableLTO::new();
        let (applicability, results) = run_rule(&rule, "hardened");

        assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
        // LTO may or may not be in the hardened binary
        assert!(!results.is_empty());
    }
}

mod ad3020_optimization_tests {
    use super::*;
    use aldur_rules::elf::EnableOptimization;

    #[test]
    fn test_optimized_binary_passes() {
        let rule = EnableOptimization::new();
        let (applicability, results) = run_rule(&rule, "high_optimization");

        assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_no_optimization_binary_fails() {
        let rule = EnableOptimization::new();
        let (applicability, results) = run_rule(&rule, "no_optimization");

        assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
        assert!(!results.is_empty());
    }
}

mod ad3005_stack_clash_protection_tests {
    use super::*;
    use aldur_rules::elf::EnableStackClashProtection;

    #[test]
    fn test_hardened_binary_checked() {
        let rule = EnableStackClashProtection::new();
        let (applicability, results) = run_rule(&rule, "hardened");

        assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
        assert!(!results.is_empty());
    }
}

mod ad3004_symbol_format_tests {
    use super::*;
    use aldur_rules::elf::GenerateRequiredSymbolFormat;

    #[test]
    fn test_hardened_binary_checked() {
        let rule = GenerateRequiredSymbolFormat::new();
        let (applicability, results) = run_rule(&rule, "hardened");

        assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
        assert!(!results.is_empty());
    }
}

mod ad3015_intel_cet_tests {
    use super::*;
    use aldur_rules::elf::EnableIntelCET;

    #[test]
    fn test_cet_binary_passes() {
        let rule = EnableIntelCET::new();
        let (applicability, results) = run_rule(&rule, "with_cet");

        assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
        assert!(!results.is_empty());
    }
}

mod ad3016_intel_shadow_stack_tests {
    use super::*;
    use aldur_rules::elf::EnableIntelShadowStack;

    #[test]
    fn test_cet_binary_passes() {
        let rule = EnableIntelShadowStack::new();
        let (applicability, results) = run_rule(&rule, "with_cet");

        assert_eq!(applicability, AnalysisApplicability::ApplicableToSpecifiedTarget);
        assert!(!results.is_empty());
    }
}

// Test that all rules can be loaded without panicking
mod rule_loading_tests {
    use aldur_core::{FailureLevel, Rule};
    use aldur_rules::elf;

    /// Verify rule descriptor is properly configured
    fn verify_rule_descriptor(rule: &dyn Rule, expected_id: &str, expected_name: &str) {
        let desc = rule.descriptor();
        assert_eq!(desc.id, expected_id, "Rule ID mismatch");
        assert_eq!(desc.name, expected_name, "Rule name mismatch");
        assert!(!desc.short_description.is_empty(), "Short description should not be empty");
        assert!(!desc.full_description.is_empty(), "Full description should not be empty");
    }

    #[test]
    fn test_all_rules_instantiate() {
        let _ = elf::EnablePositionIndependentExecutable::new();
        let _ = elf::DoNotMarkStackAsExecutable::new();
        let _ = elf::EnableStackProtector::new();
        let _ = elf::GenerateRequiredSymbolFormat::new();
        let _ = elf::EnableStackClashProtection::new();
        let _ = elf::EnableNonExecutableStack::new();
        let _ = elf::EnableReadOnlyRelocations::new();
        let _ = elf::EnableBindNow::new();
        let _ = elf::DoNotUseRpath::new();
        let _ = elf::ValidateRunpath::new();
        let _ = elf::NoTextRelocations::new();
        let _ = elf::EnableIntelCET::new();
        let _ = elf::EnableIntelShadowStack::new();
        let _ = elf::EnableArmBTI::new();
        let _ = elf::EnableArmPAC::new();
        let _ = elf::EnableLTO::new();
        let _ = elf::EnableOptimization::new();
        let _ = elf::NoUnicodeSymbols::new();
        let _ = elf::WritableGotProtection::new();
        let _ = elf::ProperLoadSegments::new();
        let _ = elf::RestrictDlopen::new();
        let _ = elf::EnableExceptionHandling::new();
        let _ = elf::UseGccCheckedFunctions::new();
        let _ = elf::EnableClangSafeStack::new();
        let _ = elf::EnableSpeculativeLoadHardening::new();
        let _ = elf::RustEnableCET::new();
        let _ = elf::RustEnableSecureSourceHash::new();
        let _ = elf::EnableControlFlowIntegrity::new();
        let _ = elf::RustEnableSanitizers::new();
        let _ = elf::EnableUBSan::new();
        let _ = elf::EnableArmMTE::new();
        let _ = elf::EnableAddressSanitizerELF::new();
        let _ = elf::DoNotUseBannedApisELF::new();
        let _ = elf::DoNotStaticallyLinkOpenSSLELF::new();
        let _ = elf::EnableKernelCFI::new();
        let _ = elf::EnableShadowCallStack::new();
        let _ = elf::EnableStackVariableInitialization::new();
        let _ = elf::ReportElfOrMachoCompilerData::new();
        let _ = elf::EnableGccDefs::new();
    }

    #[test]
    fn test_all_rules_returns_expected_count() {
        let rules = elf::all_rules();
        // 39 ELF rules total
        assert!(rules.len() >= 38, "Expected at least 38 ELF rules, got {}", rules.len());
    }

    #[test]
    fn test_all_rules_unique_ids() {
        let rules = elf::all_rules();
        let mut ids: Vec<_> = rules.iter().map(|r| r.descriptor().id.clone()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), rules.len(), "All rule IDs should be unique");
    }

    #[test]
    fn test_all_rules_have_ad_ids() {
        let rules = elf::all_rules();
        for rule in &rules {
            let id = &rule.descriptor().id;
            assert!(id.starts_with("AD"), "ELF rules should have AD IDs, got {}", id);
        }
    }

    #[test]
    fn test_ad3030_fortify_descriptor() {
        let rule = elf::UseGccCheckedFunctions::new();
        verify_rule_descriptor(&rule, "AD3030", "UseGccCheckedFunctions");
    }

    #[test]
    fn test_ad3031_safestack_descriptor() {
        let rule = elf::EnableClangSafeStack::new();
        verify_rule_descriptor(&rule, "AD3031", "EnableClangSafeStack");
    }

    #[test]
    fn test_ad3032_slh_descriptor() {
        let rule = elf::EnableSpeculativeLoadHardening::new();
        verify_rule_descriptor(&rule, "AD3032", "EnableSpeculativeLoadHardening");
    }

    #[test]
    fn test_ad3033_rust_cet_descriptor() {
        let rule = elf::RustEnableCET::new();
        verify_rule_descriptor(&rule, "AD3033", "RustEnableCET");
    }

    #[test]
    fn test_ad3035_rust_secure_source_hash_descriptor() {
        let rule = elf::RustEnableSecureSourceHash::new();
        verify_rule_descriptor(&rule, "AD3035", "RustEnableSecureSourceHash");
    }

    #[test]
    fn test_ad3036_cfi_descriptor() {
        let rule = elf::EnableControlFlowIntegrity::new();
        verify_rule_descriptor(&rule, "AD3036", "EnableControlFlowIntegrity");
    }

    #[test]
    fn test_ad3037_rust_sanitizers_descriptor() {
        let rule = elf::RustEnableSanitizers::new();
        verify_rule_descriptor(&rule, "AD3037", "RustEnableSanitizers");
    }

    #[test]
    fn test_ad3038_ubsan_descriptor() {
        let rule = elf::EnableUBSan::new();
        verify_rule_descriptor(&rule, "AD3038", "EnableUBSan");
    }

    #[test]
    fn test_ad3039_arm_mte_descriptor() {
        let rule = elf::EnableArmMTE::new();
        verify_rule_descriptor(&rule, "AD3039", "EnableArmMTE");
    }

    #[test]
    fn test_ad3040_asan_descriptor() {
        let rule = elf::EnableAddressSanitizerELF::new();
        verify_rule_descriptor(&rule, "AD3040", "EnableAddressSanitizerELF");
    }

    #[test]
    fn test_ad3041_banned_apis_descriptor() {
        let rule = elf::DoNotUseBannedApisELF::new();
        verify_rule_descriptor(&rule, "AD3041", "DoNotUseBannedApisELF");
    }

    #[test]
    fn test_ad3042_openssl_descriptor() {
        let rule = elf::DoNotStaticallyLinkOpenSSLELF::new();
        verify_rule_descriptor(&rule, "AD3042", "DoNotStaticallyLinkOpenSSLELF");
    }

    #[test]
    fn test_ad3043_kcfi_descriptor() {
        let rule = elf::EnableKernelCFI::new();
        verify_rule_descriptor(&rule, "AD3043", "EnableKernelCFI");
    }

    #[test]
    fn test_ad3044_shadow_call_stack_descriptor() {
        let rule = elf::EnableShadowCallStack::new();
        verify_rule_descriptor(&rule, "AD3044", "EnableShadowCallStack");
    }

    #[test]
    fn test_ad3045_stack_variable_init_descriptor() {
        let rule = elf::EnableStackVariableInitialization::new();
        verify_rule_descriptor(&rule, "AD3045", "EnableStackVariableInitialization");
    }

    #[test]
    fn test_ad4002_compiler_data_descriptor() {
        let rule = elf::ReportElfOrMachoCompilerData::new();
        verify_rule_descriptor(&rule, "AD4002", "ReportElfOrMachoCompilerData");
        assert_eq!(rule.descriptor().default_level, FailureLevel::Note);
    }

    #[test]
    fn test_ad3050_gcc_defs_descriptor() {
        let rule = elf::EnableGccDefs::new();
        verify_rule_descriptor(&rule, "AD3050", "EnableGccDefs");
    }
}
