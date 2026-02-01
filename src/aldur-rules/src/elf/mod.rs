//! ELF (Linux/Unix) security rules

mod ad3001_enable_pie;
mod ad3002_do_not_mark_stack_executable;
mod ad3003_enable_stack_protector;
mod ad3004_generate_required_symbol_format;
mod ad3005_enable_stack_clash_protection;
mod ad3006_enable_non_executable_stack;
mod ad3010_enable_relro;
mod ad3011_enable_bind_now;
mod ad3012_do_not_use_rpath;
mod ad3013_validate_runpath;
mod ad3014_no_text_relocations;
mod ad3015_enable_intel_cet;
mod ad3016_enable_intel_shadow_stack;
mod ad3017_enable_arm_bti;
mod ad3018_enable_arm_pac;
mod ad3019_enable_lto;
mod ad3020_enable_optimization;
mod ad3021_no_unicode_symbols;
mod ad3022_writable_got_protection;
mod ad3023_proper_load_segments;
mod ad3024_restrict_dlopen;
mod ad3025_enable_exception_handling;
mod ad3030_use_fortified_functions;
mod ad3031_enable_clang_safestack;
mod ad3032_enable_speculative_load_hardening;
mod ad3033_rust_enable_cet;
mod ad3035_rust_enable_secure_source_hash;
mod ad3036_enable_control_flow_integrity;
mod ad3037_rust_enable_sanitizers;
mod ad3038_enable_ubsan;
mod ad3039_enable_arm_mte;
mod ad3040_enable_address_sanitizer;
mod ad3041_do_not_use_banned_apis;
mod ad3042_do_not_statically_link_openssl;
mod ad3043_enable_kcfi;
mod ad3044_enable_shadow_call_stack;
mod ad3045_enable_stack_variable_init;
mod ad3050_enable_gcc_defs;
mod ad3051_check_fortify_level;
mod ad4002_report_elf_macho_compiler_data;
pub mod compiler_utils;

pub use ad3001_enable_pie::EnablePositionIndependentExecutable;
pub use ad3002_do_not_mark_stack_executable::DoNotMarkStackAsExecutable;
pub use ad3003_enable_stack_protector::EnableStackProtector;
pub use ad3004_generate_required_symbol_format::GenerateRequiredSymbolFormat;
pub use ad3005_enable_stack_clash_protection::EnableStackClashProtection;
pub use ad3006_enable_non_executable_stack::EnableNonExecutableStack;
pub use ad3010_enable_relro::EnableReadOnlyRelocations;
pub use ad3011_enable_bind_now::EnableBindNow;
pub use ad3012_do_not_use_rpath::DoNotUseRpath;
pub use ad3013_validate_runpath::ValidateRunpath;
pub use ad3014_no_text_relocations::NoTextRelocations;
pub use ad3015_enable_intel_cet::EnableIntelCET;
pub use ad3016_enable_intel_shadow_stack::EnableIntelShadowStack;
pub use ad3017_enable_arm_bti::EnableArmBTI;
pub use ad3018_enable_arm_pac::EnableArmPAC;
pub use ad3019_enable_lto::EnableLTO;
pub use ad3020_enable_optimization::EnableOptimization;
pub use ad3021_no_unicode_symbols::NoUnicodeSymbols;
pub use ad3022_writable_got_protection::WritableGotProtection;
pub use ad3023_proper_load_segments::ProperLoadSegments;
pub use ad3024_restrict_dlopen::RestrictDlopen;
pub use ad3025_enable_exception_handling::EnableExceptionHandling;
pub use ad3030_use_fortified_functions::UseGccCheckedFunctions;
pub use ad3031_enable_clang_safestack::EnableClangSafeStack;
pub use ad3032_enable_speculative_load_hardening::EnableSpeculativeLoadHardening;
pub use ad3033_rust_enable_cet::RustEnableCET;
pub use ad3035_rust_enable_secure_source_hash::RustEnableSecureSourceHash;
pub use ad3036_enable_control_flow_integrity::EnableControlFlowIntegrity;
pub use ad3037_rust_enable_sanitizers::RustEnableSanitizers;
pub use ad3038_enable_ubsan::EnableUBSan;
pub use ad3039_enable_arm_mte::EnableArmMTE;
pub use ad3040_enable_address_sanitizer::EnableAddressSanitizerELF;
pub use ad3041_do_not_use_banned_apis::DoNotUseBannedApisELF;
pub use ad3042_do_not_statically_link_openssl::DoNotStaticallyLinkOpenSSLELF;
pub use ad3043_enable_kcfi::EnableKernelCFI;
pub use ad3044_enable_shadow_call_stack::EnableShadowCallStack;
pub use ad3045_enable_stack_variable_init::EnableStackVariableInitialization;
pub use ad3050_enable_gcc_defs::EnableGccDefs;
pub use ad3051_check_fortify_level::CheckFortifySourceLevel;
pub use ad4002_report_elf_macho_compiler_data::ReportElfOrMachoCompilerData;

use aldur_core::Rule;

/// Get all ELF rules
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(EnablePositionIndependentExecutable::new()),
        Box::new(DoNotMarkStackAsExecutable::new()),
        Box::new(EnableStackProtector::new()),
        Box::new(GenerateRequiredSymbolFormat::new()),
        Box::new(EnableStackClashProtection::new()),
        Box::new(EnableNonExecutableStack::new()),
        Box::new(EnableReadOnlyRelocations::new()),
        Box::new(EnableBindNow::new()),
        Box::new(DoNotUseRpath::new()),
        Box::new(ValidateRunpath::new()),
        Box::new(NoTextRelocations::new()),
        Box::new(EnableIntelCET::new()),
        Box::new(EnableIntelShadowStack::new()),
        Box::new(EnableArmBTI::new()),
        Box::new(EnableArmPAC::new()),
        Box::new(EnableLTO::new()),
        Box::new(EnableOptimization::new()),
        Box::new(NoUnicodeSymbols::new()),
        Box::new(WritableGotProtection::new()),
        Box::new(ProperLoadSegments::new()),
        Box::new(RestrictDlopen::new()),
        Box::new(EnableExceptionHandling::new()),
        Box::new(UseGccCheckedFunctions::new()),
        Box::new(EnableClangSafeStack::new()),
        Box::new(EnableSpeculativeLoadHardening::new()),
        Box::new(RustEnableCET::new()),
        Box::new(RustEnableSecureSourceHash::new()),
        Box::new(EnableControlFlowIntegrity::new()),
        Box::new(RustEnableSanitizers::new()),
        Box::new(EnableUBSan::new()),
        Box::new(EnableArmMTE::new()),
        Box::new(EnableAddressSanitizerELF::new()),
        Box::new(DoNotUseBannedApisELF::new()),
        Box::new(DoNotStaticallyLinkOpenSSLELF::new()),
        Box::new(EnableKernelCFI::new()),
        Box::new(EnableShadowCallStack::new()),
        Box::new(EnableStackVariableInitialization::new()),
        Box::new(ReportElfOrMachoCompilerData::new()),
        Box::new(EnableGccDefs::new()),
        Box::new(CheckFortifySourceLevel::new()),
    ]
}
