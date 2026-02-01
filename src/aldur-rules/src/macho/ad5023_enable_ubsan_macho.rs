//! AD5023: EnableUBSanMachO
//!
//! Checks that UndefinedBehaviorSanitizer (UBSan) is enabled in Mach-O binaries.
//! UBSan detects undefined behavior at runtime, such as integer overflow,
//! null pointer dereference, and type mismatches.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::MachOBinary;

use crate::rule_ids::AD5023;

/// UBSan handler symbols to look for
const UBSAN_SYMBOLS: &[&str] = &[
    "__ubsan_handle_add_overflow",
    "__ubsan_handle_sub_overflow",
    "__ubsan_handle_mul_overflow",
    "__ubsan_handle_divrem_overflow",
    "__ubsan_handle_negate_overflow",
    "__ubsan_handle_pointer_overflow",
    "__ubsan_handle_shift_out_of_bounds",
    "__ubsan_handle_out_of_bounds",
    "__ubsan_handle_type_mismatch",
    "__ubsan_handle_type_mismatch_v1",
    "__ubsan_handle_vla_bound_not_positive",
    "__ubsan_handle_float_cast_overflow",
    "__ubsan_handle_load_invalid_value",
    "__ubsan_handle_invalid_builtin",
    "__ubsan_handle_function_type_mismatch",
    "__ubsan_handle_nonnull_arg",
    "__ubsan_handle_nonnull_return",
    "__ubsan_handle_nullability_arg",
    "__ubsan_handle_nullability_return",
    "__ubsan_handle_missing_return",
    "__ubsan_handle_alignment_assumption",
    "__ubsan_handle_builtin_unreachable",
    "__ubsan_handle_cfi_check_fail",
];

pub struct EnableUBSanMachO {
    descriptor: RuleDescriptor,
}

impl EnableUBSanMachO {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD5023, "EnableUBSanMachO")
            .with_category(RuleCategory::Security)
            .with_tags(&["debug-only", "memory-safety", "macos-only"])
            .with_short_description("Enable UndefinedBehaviorSanitizer (UBSan) for runtime detection of undefined behavior.")
            .with_full_description(
                "UndefinedBehaviorSanitizer (UBSan) is a runtime checker that detects various \
                 forms of undefined behavior in C/C++ programs, including integer overflow, \
                 null pointer dereference, out-of-bounds array access, and type mismatches. \
                 UBSan helps identify bugs that could lead to security vulnerabilities. \
                 Note: Sanitizers are typically used in debug/test builds, not production \
                 builds, due to performance overhead. Compile with '-fsanitize=undefined' \
                 to enable UBSan. For Rust, use '-Zsanitizer=undefined' (nightly only).",
            )
            .with_fix_hint("Compile with -fsanitize=undefined (debug builds only)")
            .with_default_level(FailureLevel::Note)
            .with_message(
                "Pass",
                "'{0}' has UndefinedBehaviorSanitizer (UBSan) enabled.",
            )
            .with_message(
                "Note",
                "'{0}' does not have UndefinedBehaviorSanitizer (UBSan) enabled. Consider \
                 compiling debug/test builds with '-fsanitize=undefined' to detect undefined \
                 behavior at runtime.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for EnableUBSanMachO {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableUBSanMachO {
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

        if binary.format() != BinaryFormat::MachO {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Not a Mach-O binary".to_string()),
            );
        }

        let macho = match binary.as_ref().as_any().downcast_ref::<MachOBinary>() {
            Some(macho) => macho,
            None => {
                return (
                    AnalysisApplicability::NotApplicableToSpecifiedTarget,
                    Some("Could not access Mach-O data".to_string()),
                );
            }
        };

        use aldur_parsers::macho::MachOType;

        // Skip object files and core dumps
        match macho.file_type() {
            Some(MachOType::Object) | Some(MachOType::Core) | Some(MachOType::Dsym) => {
                return (
                    AnalysisApplicability::NotApplicableToSpecifiedTarget,
                    Some("Mach-O is object file, core dump, or dsym".to_string()),
                );
            }
            _ => {}
        }

        (AnalysisApplicability::ApplicableToSpecifiedTarget, None)
    }

    fn analyze(&self, context: &mut AnalysisContext) {
        let file_name = context.file_name();
        let binary = context.binary().expect("Binary must be loaded").clone();

        let macho = match binary.as_ref().as_any().downcast_ref::<MachOBinary>() {
            Some(macho) => macho,
            None => {
                self.log_not_applicable(
                    context,
                    "NotApplicable_InvalidMetadata",
                    &[&file_name, self.name(), "Could not access Mach-O data"],
                );
                return;
            }
        };

        if macho.has_any_symbol(UBSAN_SYMBOLS) {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(context, FailureLevel::Note, "Note", &[&file_name]);
        }
    }
}
