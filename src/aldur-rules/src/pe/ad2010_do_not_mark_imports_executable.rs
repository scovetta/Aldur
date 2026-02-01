//! AD2010: DoNotMarkImportsSectionAsExecutable
//!
//! PE sections should not be marked as both writable and executable.
//! The imports section should not be executable.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::PeBinary;

use crate::rule_ids::AD2010;

pub struct DoNotMarkImportsSectionAsExecutable {
    descriptor: RuleDescriptor,
}

impl DoNotMarkImportsSectionAsExecutable {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2010, "DoNotMarkImportsSectionAsExecutable")
            .with_category(RuleCategory::Security)
            .with_tags(&["critical", "memory-safety", "windows-only"])
            .with_short_description("The imports section should not be marked as executable.")
            .with_full_description(
                "PE sections should not be marked as both writable and executable. This \
                 condition makes it easier for an attacker to exploit memory corruption \
                 vulnerabilities, as it may provide an attacker executable location(s) to \
                 inject shellcode. Because the loader will always mark the imports section \
                 as writable, it is therefore important to mark this section as non-executable.",
            )
            .with_fix_hint("Ensure imports section is not marked as executable in linker settings")
            .with_default_level(FailureLevel::Error)
            .with_message(
                "Pass",
                "'{0}' does not have an imports section that is marked as executable, \
                 helping to prevent the exploitation of code vulnerabilities.",
            )
            .with_message(
                "Error",
                "'{0}' has the imports section marked executable. Because the loader will \
                 always mark the imports section as writable, it is important to mark this \
                 section as non-executable, so that an attacker cannot place shellcode here.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for DoNotMarkImportsSectionAsExecutable {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DoNotMarkImportsSectionAsExecutable {
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

        if pe.imports_section_executable() {
            self.log_fail(context, FailureLevel::Error, "Error", &[&file_name]);
        } else {
            self.log_pass(context, "Pass", &[&file_name]);
        }
    }
}
