//! Mach-O (macOS/iOS) security rules

mod ad5001_enable_pie;
mod ad5002_do_not_allow_executable_stack;
mod ad5003_enable_stack_protector;
mod ad5004_use_fortified_functions;
mod ad5005_do_not_allow_executable_heap;
mod ad5006_use_two_level_namespace;
mod ad5007_enable_arm_pac;
mod ad5008_enable_clang_safestack;
mod ad5009_do_not_use_weak_dylib;
mod ad5010_enable_arc;
mod ad5011_require_code_signature;
mod ad5012_validate_segment_permissions;
mod ad5013_do_not_use_banned_apis;
mod ad5014_use_address_sanitizer;
mod ad5015_do_not_statically_link_openssl;
mod ad5016_no_unicode_symbols;
mod ad5017_enable_lto;
mod ad5018_require_minimum_os_version;
mod ad5019_use_restrict_segment;
mod ad5020_rust_enable_sanitizers_macho;
mod ad5021_rust_enable_secure_source_hash_macho;
mod ad5022_rust_macho_enable_lto;
mod ad5023_enable_ubsan_macho;
mod ad5024_enable_stack_clash_protection;
mod ad5025_enable_control_flow_integrity;
mod ad5026_enable_arm_bti;
mod ad5027_enable_speculative_load_hardening;
mod ad5028_enable_optimization;
mod ad5029_enable_arm_mte;
mod ad5030_enable_exception_handling;
mod ad5031_check_not_encrypted;
mod ad5040_do_not_use_unchecked_optimization;
mod ad5060_detect_packed_binary;

pub use ad5001_enable_pie::EnablePositionIndependentExecutableMachO;
pub use ad5002_do_not_allow_executable_stack::DoNotAllowExecutableStack;
pub use ad5003_enable_stack_protector::EnableStackProtectorMachO;
pub use ad5004_use_fortified_functions::UseFortifiedFunctionsMachO;
pub use ad5005_do_not_allow_executable_heap::DoNotAllowExecutableHeap;
pub use ad5006_use_two_level_namespace::UseTwoLevelNamespace;
pub use ad5007_enable_arm_pac::EnableArmPACMachO;
pub use ad5008_enable_clang_safestack::EnableClangSafeStackMachO;
pub use ad5009_do_not_use_weak_dylib::DoNotUseWeakDylib;
pub use ad5010_enable_arc::EnableAutomaticReferenceCounting;
pub use ad5011_require_code_signature::RequireCodeSignature;
pub use ad5012_validate_segment_permissions::ValidateSegmentPermissions;
pub use ad5013_do_not_use_banned_apis::DoNotUseBannedApisMachO;
pub use ad5014_use_address_sanitizer::UseAddressSanitizer;
pub use ad5015_do_not_statically_link_openssl::DoNotStaticallyLinkOpenSSL;
pub use ad5016_no_unicode_symbols::NoUnicodeSymbolsMachO;
pub use ad5017_enable_lto::EnableLTOMachO;
pub use ad5018_require_minimum_os_version::RequireMinimumOSVersion;
pub use ad5019_use_restrict_segment::UseRestrictSegment;
pub use ad5020_rust_enable_sanitizers_macho::RustEnableSanitizersMachO;
pub use ad5021_rust_enable_secure_source_hash_macho::RustEnableSecureSourceHashMachO;
pub use ad5022_rust_macho_enable_lto::RustMachOEnableLTO;
pub use ad5023_enable_ubsan_macho::EnableUBSanMachO;
pub use ad5024_enable_stack_clash_protection::EnableStackClashProtectionMachO;
pub use ad5025_enable_control_flow_integrity::EnableControlFlowIntegrityMachO;
pub use ad5026_enable_arm_bti::EnableArmBTIMachO;
pub use ad5027_enable_speculative_load_hardening::EnableSpeculativeLoadHardeningMachO;
pub use ad5028_enable_optimization::EnableOptimizationMachO;
pub use ad5029_enable_arm_mte::EnableArmMTEMachO;
pub use ad5030_enable_exception_handling::EnableExceptionHandlingMachO;
pub use ad5031_check_not_encrypted::CheckNotEncrypted;
pub use ad5040_do_not_use_unchecked_optimization::DoNotUseUncheckedOptimization;
pub use ad5060_detect_packed_binary::DetectPackedBinaryMachO;

use aldur_core::Rule;

/// Get all Mach-O rules
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(EnablePositionIndependentExecutableMachO::new()),
        Box::new(DoNotAllowExecutableStack::new()),
        Box::new(EnableStackProtectorMachO::new()),
        Box::new(UseFortifiedFunctionsMachO::new()),
        Box::new(DoNotAllowExecutableHeap::new()),
        Box::new(UseTwoLevelNamespace::new()),
        Box::new(EnableArmPACMachO::new()),
        Box::new(EnableClangSafeStackMachO::new()),
        Box::new(DoNotUseWeakDylib::new()),
        Box::new(EnableAutomaticReferenceCounting::new()),
        Box::new(RequireCodeSignature::new()),
        Box::new(ValidateSegmentPermissions::new()),
        Box::new(DoNotUseBannedApisMachO::new()),
        Box::new(UseAddressSanitizer::new()),
        Box::new(DoNotStaticallyLinkOpenSSL::new()),
        Box::new(NoUnicodeSymbolsMachO::new()),
        Box::new(EnableLTOMachO::new()),
        Box::new(RequireMinimumOSVersion::new()),
        Box::new(UseRestrictSegment::new()),
        Box::new(RustEnableSanitizersMachO::new()),
        Box::new(RustEnableSecureSourceHashMachO::new()),
        Box::new(RustMachOEnableLTO::new()),
        Box::new(EnableUBSanMachO::new()),
        Box::new(EnableStackClashProtectionMachO::new()),
        Box::new(EnableControlFlowIntegrityMachO::new()),
        Box::new(EnableArmBTIMachO::new()),
        Box::new(EnableSpeculativeLoadHardeningMachO::new()),
        Box::new(EnableOptimizationMachO::new()),
        Box::new(EnableArmMTEMachO::new()),
        Box::new(EnableExceptionHandlingMachO::new()),
        Box::new(CheckNotEncrypted::new()),
        Box::new(DoNotUseUncheckedOptimization::new()),
        Box::new(DetectPackedBinaryMachO::new()),
    ]
}
