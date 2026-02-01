//! AD5014: UseAddressSanitizer
//!
//! Checks that debug/test builds use AddressSanitizer (ASAN) for memory error detection.
//! This is an informational check - ASAN is typically used in development, not production.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::MachOBinary;

use crate::rule_ids::AD5014;

/// ASAN symbols that indicate AddressSanitizer is enabled
const ASAN_SYMBOLS: &[&str] = &[
    "__asan_init",
    "__asan_report_load",
    "__asan_report_store",
    "__asan_register_globals",
    "__asan_version_mismatch_check",
    "___asan_init",
];

pub struct UseAddressSanitizer {
    descriptor: RuleDescriptor,
}

impl UseAddressSanitizer {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD5014, "UseAddressSanitizer")
            .with_category(RuleCategory::Security)
            .with_tags(&["debug-only", "memory-safety", "macos-only"])
            .with_short_description("Use AddressSanitizer for memory error detection (debug builds).")
            .with_full_description(
                "AddressSanitizer (ASAN) is a fast memory error detector that catches buffer \
                 overflows, use-after-free, and other memory errors at runtime. It should be \
                 enabled during development and testing with '-fsanitize=address'. Note: ASAN \
                 is typically not used in production due to performance overhead.",
            )
            .with_fix_hint("Compile with -fsanitize=address (debug builds only)")
            .with_default_level(FailureLevel::Note)
            .with_message(
                "Pass",
                "'{0}' has AddressSanitizer enabled.",
            )
            .with_message(
                "Note",
                "'{0}' does not have AddressSanitizer enabled. Consider using ASAN in debug \
                 builds with '-fsanitize=address' to catch memory errors during development.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for UseAddressSanitizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for UseAddressSanitizer {
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

        if macho.has_any_symbol(ASAN_SYMBOLS) {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(context, FailureLevel::Note, "Note", &[&file_name]);
        }
    }
}
