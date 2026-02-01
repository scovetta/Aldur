//! AD2021: DoNotMarkWritableSectionsAsExecutable
//!
//! PE sections should not be marked as both writable and executable.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::PeBinary;

use crate::rule_ids::AD2021;

pub struct DoNotMarkWritableSectionsAsExecutable {
    descriptor: RuleDescriptor,
}

impl DoNotMarkWritableSectionsAsExecutable {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2021, "DoNotMarkWritableSectionsAsExecutable")
            .with_category(RuleCategory::Security)
            .with_tags(&["critical", "memory-safety", "windows-only"])
            .with_short_description(
                "PE sections should not be marked as both writable and executable.",
            )
            .with_full_description(
                "PE sections should not be marked as both writable and executable. This \
                 condition makes it easier for an attacker to exploit memory corruption \
                 vulnerabilities, as it may provide an attacker executable location(s) to \
                 inject shellcode. To resolve this issue, configure your tools to not emit \
                 memory sections that are writable and executable. Be sure to disable \
                 incremental linking in release builds, as this feature creates a writable \
                 and executable section named '.textbss'.",
            )
            .with_fix_hint("Disable incremental linking with /INCREMENTAL:NO")
            .with_default_level(FailureLevel::Error)
            .with_message(
                "Pass",
                "'{0}' contains no data or code sections marked as both shared and executable, \
                 helping to prevent the exploitation of code vulnerabilities.",
            )
            .with_message(
                "Error",
                "'{0}' contains PE section(s) ({1}) that are both writable and executable. \
                 Writable and executable memory segments make it easier for an attacker to \
                 exploit memory corruption vulnerabilities. Enabling incremental linking via \
                 the /INCREMENTAL argument can also result in a writable and executable section \
                 named 'textbss'. Disable incremental linking to resolve this problem.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for DoNotMarkWritableSectionsAsExecutable {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DoNotMarkWritableSectionsAsExecutable {
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

        let bad_sections = pe.writable_executable_sections();

        if bad_sections.is_empty() {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            let sections_str: Vec<&str> = bad_sections.iter().map(|s| s.name.as_str()).collect();
            let sections_list = sections_str.join(", ");
            self.log_fail(
                context,
                FailureLevel::Error,
                "Error",
                &[&file_name, &sections_list],
            );
        }
    }
}
