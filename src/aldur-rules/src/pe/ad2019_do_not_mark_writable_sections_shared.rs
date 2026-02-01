//! AD2019: DoNotMarkWritableSectionsAsShared
//!
//! Code or data sections should not be marked as both shared and writable.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::PeBinary;

use crate::rule_ids::AD2019;

pub struct DoNotMarkWritableSectionsAsShared {
    descriptor: RuleDescriptor,
}

impl DoNotMarkWritableSectionsAsShared {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2019, "DoNotMarkWritableSectionsAsShared")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "memory-safety", "windows-only"])
            .with_short_description(
                "Code or data sections should not be marked as both shared and writable.",
            )
            .with_full_description(
                "Code or data sections should not be marked as both shared and writable. \
                 Because these sections are shared across processes, this condition might \
                 permit a process with low privilege to alter memory in a higher privilege \
                 process. If you do not actually require that a section be both writable and \
                 shared, remove one or both of these attributes.",
            )
            .with_fix_hint("Remove /SECTION with SHARED attribute for writable sections")
            .with_default_level(FailureLevel::Error)
            .with_message(
                "Pass",
                "'{0}' contains no data or code sections marked as both shared and writable, \
                 helping to prevent the exploitation of code vulnerabilities.",
            )
            .with_message(
                "Error",
                "'{0}' contains one or more code or data sections ({1}) which are marked as \
                 both shared and writable. Because these sections are shared across processes, \
                 this condition might permit a process with low privilege to alter memory in a \
                 higher privilege process.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for DoNotMarkWritableSectionsAsShared {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DoNotMarkWritableSectionsAsShared {
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

        // Find sections that are both writable and shared
        let bad_sections: Vec<&str> = pe
            .sections
            .iter()
            .filter(|s| s.is_writable() && s.is_shared())
            .map(|s| s.name.as_str())
            .collect();

        if bad_sections.is_empty() {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            let sections_str = bad_sections.join(", ");
            self.log_fail(
                context,
                FailureLevel::Error,
                "Error",
                &[&file_name, &sections_str],
            );
        }
    }
}
