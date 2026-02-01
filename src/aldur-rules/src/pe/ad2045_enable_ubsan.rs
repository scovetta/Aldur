//! AD2045: EnableUBSanPE
//!
//! Checks that PE binaries compiled with GCC/Clang have UndefinedBehaviorSanitizer (UBSan) enabled.
//! This is an informational check - UBSan is typically used in development, not production.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::PeBinary;

use crate::rule_ids::AD2045;

/// UBSan symbols that indicate UndefinedBehaviorSanitizer is enabled
const UBSAN_SYMBOLS: &[&str] = &[
    "__ubsan_handle_add_overflow",
    "__ubsan_handle_sub_overflow",
    "__ubsan_handle_mul_overflow",
    "__ubsan_handle_divrem_overflow",
    "__ubsan_handle_negate_overflow",
    "__ubsan_handle_shift_out_of_bounds",
    "__ubsan_handle_type_mismatch",
    "__ubsan_handle_out_of_bounds",
    "__ubsan_handle_builtin_unreachable",
    "__ubsan_handle_missing_return",
    "__ubsan_handle_vla_bound_not_positive",
    "__ubsan_handle_float_cast_overflow",
    "__ubsan_handle_load_invalid_value",
    "__ubsan_handle_nonnull_arg",
    "__ubsan_handle_nonnull_return",
    "__ubsan_handle_pointer_overflow",
];

pub struct EnableUBSanPE {
    descriptor: RuleDescriptor,
}

impl EnableUBSanPE {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2045, "EnableUBSanPE")
            .with_category(RuleCategory::Security)
            .with_tags(&["debug-only", "memory-safety", "windows-only"])
            .with_short_description("Use UndefinedBehaviorSanitizer for detecting undefined behavior (debug builds).")
            .with_full_description(
                "UndefinedBehaviorSanitizer (UBSan) is a runtime checker for undefined behavior \
                 in C/C++ programs. It can detect issues like integer overflow, null pointer \
                 dereference, and type confusion. For PE files compiled with GCC or Clang, \
                 consider using '-fsanitize=undefined' during development and testing.",
            )
            .with_fix_hint("Compile with -fsanitize=undefined (debug builds only)")
            .with_default_level(FailureLevel::Note)
            .with_message(
                "Pass",
                "'{0}' has UndefinedBehaviorSanitizer (UBSan) enabled.",
            )
            .with_message(
                "Pass_DwarfConfirmed",
                "'{0}' has UBSan enabled (confirmed via DWARF debug info).",
            )
            .with_message(
                "Note",
                "'{0}' does not have UBSan enabled. For GCC/Clang builds, consider using \
                 '-fsanitize=undefined' in debug builds to detect undefined behavior.",
            )
            .with_message(
                "NotApplicable_NotGccClang",
                "'{0}' was not compiled with GCC/Clang. UBSan check only applies to GCC/Clang builds.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }

    /// Check for UBSan indicators
    fn check_ubsan(pe: &PeBinary) -> (bool, bool, bool) {
        let mut is_gcc_clang = false;

        // Check DWARF for UBSan flags
        if let Some(dwarf_info) = pe.dwarf_info() {
            if dwarf_info.has_debug_info && !dwarf_info.compilation_units.is_empty() {
                // Check if GCC or Clang
                for cu in &dwarf_info.compilation_units {
                    use aldur_parsers::dwarf::CompilerType;
                    match cu.parsed_info.compiler_type {
                        CompilerType::Gcc | CompilerType::Clang => {
                            is_gcc_clang = true;
                        }
                        _ => {}
                    }
                }

                let has_ubsan = dwarf_info.has_flag("-fsanitize=undefined")
                    || dwarf_info.has_flag("sanitize=undefined");

                if has_ubsan {
                    return (true, true, is_gcc_clang);
                }
            }
        }

        // Check for UBSan-related symbols/imports (heuristic)
        let has_ubsan_symbols = UBSAN_SYMBOLS.iter().any(|sym| pe.has_import(sym));

        (has_ubsan_symbols, false, is_gcc_clang)
    }
}

impl Default for EnableUBSanPE {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableUBSanPE {
    fn descriptor(&self) -> &RuleDescriptor {
        &self.descriptor
    }

    fn can_analyze(
        &self,
        context: &AnalysisContext,
    ) -> (AnalysisApplicability, Option<String>) {
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

        let (has_ubsan, is_definitive, is_gcc_clang) = Self::check_ubsan(pe);

        // If we can determine it's not GCC/Clang, mark as not applicable
        // But we'll still check for UBSan symbols as a fallback
        if !is_gcc_clang && !has_ubsan {
            // Can't determine compiler - still provide the informational check
            self.log_fail(context, FailureLevel::Note, "Note", &[&file_name]);
            return;
        }

        if has_ubsan {
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
