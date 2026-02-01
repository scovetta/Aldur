//! AD2046: EnableAddressSanitizerPE
//!
//! Checks that PE binaries compiled with GCC/Clang have AddressSanitizer (ASAN) enabled.
//! This is an informational check - ASAN is typically used in development, not production.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::PeBinary;

use crate::rule_ids::AD2046;

/// ASAN symbols that indicate AddressSanitizer is enabled
const ASAN_SYMBOLS: &[&str] = &[
    "__asan_init",
    "__asan_report_load",
    "__asan_report_store",
    "__asan_register_globals",
    "__asan_version_mismatch_check",
    "__asan_load1",
    "__asan_load2",
    "__asan_load4",
    "__asan_load8",
    "__asan_store1",
    "__asan_store2",
    "__asan_store4",
    "__asan_store8",
    "__asan_handle_no_return",
];

pub struct EnableAddressSanitizerPE {
    descriptor: RuleDescriptor,
}

impl EnableAddressSanitizerPE {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2046, "EnableAddressSanitizerPE")
            .with_category(RuleCategory::Security)
            .with_tags(&["debug-only", "memory-safety", "windows-only"])
            .with_short_description(
                "Use AddressSanitizer for memory error detection (debug builds).",
            )
            .with_full_description(
                "AddressSanitizer (ASAN) is a fast memory error detector that catches buffer \
                 overflows, use-after-free, and other memory errors at runtime. For PE files \
                 compiled with GCC or Clang, consider using '-fsanitize=address' during \
                 development and testing. Note: ASAN has ~2x performance overhead.",
            )
            .with_fix_hint("Compile with -fsanitize=address (debug builds only)")
            .with_default_level(FailureLevel::Note)
            .with_message("Pass", "'{0}' has AddressSanitizer enabled.")
            .with_message(
                "Pass_DwarfConfirmed",
                "'{0}' has AddressSanitizer enabled (confirmed via DWARF debug info).",
            )
            .with_message(
                "Note",
                "'{0}' does not have AddressSanitizer enabled. For GCC/Clang builds, consider \
                 using '-fsanitize=address' in debug builds to catch memory errors.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }

    /// Check for ASAN indicators
    fn check_asan(pe: &PeBinary) -> (bool, bool) {
        // Check DWARF for ASAN flags
        if let Some(dwarf_info) = pe.dwarf_info() {
            if dwarf_info.has_debug_info && !dwarf_info.compilation_units.is_empty() {
                let has_asan = dwarf_info.has_flag("-fsanitize=address")
                    || dwarf_info.has_flag("sanitize=address");

                if has_asan {
                    return (true, true);
                }
            }
        }

        // Check for ASAN-related symbols/imports (heuristic)
        let has_asan_symbols = ASAN_SYMBOLS.iter().any(|sym| pe.has_import(sym));

        (has_asan_symbols, false)
    }
}

impl Default for EnableAddressSanitizerPE {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableAddressSanitizerPE {
    fn descriptor(&self) -> &RuleDescriptor {
        &self.descriptor
    }

    fn can_analyze(&self, context: &AnalysisContext) -> (AnalysisApplicability, Option<String>) {
        let Some(binary) = context.binary() else {
            return (
                AnalysisApplicability::NotApplicableDueToMissingTarget,
                Some("Binary not loaded".to_string()),
            );
        };

        if binary.format() != BinaryFormat::PE {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Not a PE binary".to_string()),
            );
        }

        (AnalysisApplicability::ApplicableToSpecifiedTarget, None)
    }

    fn analyze(&self, context: &mut AnalysisContext) {
        let file_name = context.file_name();
        let binary = context.binary().expect("Binary must be loaded").clone();

        let pe = match binary.as_ref().as_any().downcast_ref::<PeBinary>() {
            Some(pe) => pe,
            None => {
                self.log_not_applicable(
                    context,
                    "NotApplicable_InvalidMetadata",
                    &[&file_name, self.name(), "Could not access PE data"],
                );
                return;
            }
        };

        let (has_asan, is_definitive) = Self::check_asan(pe);

        if has_asan {
            if is_definitive {
                self.log_pass(context, "Pass_DwarfConfirmed", &[&file_name]);
            } else {
                self.log_pass(context, "Pass", &[&file_name]);
            }
        } else {
            self.log_fail(context, FailureLevel::Note, "Note", &[&file_name]);
        }
    }
}
