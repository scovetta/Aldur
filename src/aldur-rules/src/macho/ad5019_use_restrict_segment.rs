//! AD5019: UseRestrictSegment
//!
//! Checks that Mach-O binaries have a __RESTRICT segment, which provides
//! additional runtime protections by disabling certain dyld environment variables.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::MachOBinary;

use crate::rule_ids::AD5019;

pub struct UseRestrictSegment {
    descriptor: RuleDescriptor,
}

impl UseRestrictSegment {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD5019, "UseRestrictSegment")
            .with_category(RuleCategory::Security)
            .with_tags(&["hardening", "macos-only"])
            .with_short_description("Use __RESTRICT segment for enhanced runtime security.")
            .with_full_description(
                "The __RESTRICT segment (with __restrict section) disables certain dyld \
                 environment variables like DYLD_INSERT_LIBRARIES that could be used to \
                 inject malicious code. This provides defense-in-depth against library \
                 injection attacks. Add with '-Wl,-sectcreate,__RESTRICT,__restrict,/dev/null'.",
            )
            .with_fix_hint("Link with -Wl,-sectcreate,__RESTRICT,__restrict,/dev/null")
            .with_default_level(FailureLevel::Note)
            .with_message(
                "Pass",
                "'{0}' has a __RESTRICT segment for enhanced runtime security.",
            )
            .with_message(
                "Note",
                "'{0}' does not have a __RESTRICT segment. Consider adding one with \
                 '-Wl,-sectcreate,__RESTRICT,__restrict,/dev/null' to prevent \
                 DYLD_INSERT_LIBRARIES injection.",
            )
            .with_message(
                "NotApplicable_NotExecutable",
                "'{0}' is not an executable. __RESTRICT segment only applies to executables.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for UseRestrictSegment {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for UseRestrictSegment {
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

        // Only applies to executables
        if !macho.is_executable() {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Not an executable".to_string()),
            );
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

        if !macho.is_executable() {
            self.log_not_applicable(context, "NotApplicable_NotExecutable", &[&file_name]);
            return;
        }

        if macho.has_restrict_segment {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(context, FailureLevel::Note, "Note", &[&file_name]);
        }
    }
}
