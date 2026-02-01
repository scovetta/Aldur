//! AD2052: RequireAuthenticode
//!
//! Checks that PE binaries have Authenticode signatures.
//! Code signing helps verify the authenticity and integrity of binaries.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::PeBinary;

use crate::rule_ids::AD2052;

pub struct RequireAuthenticode {
    descriptor: RuleDescriptor,
}

impl RequireAuthenticode {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2052, "RequireAuthenticode")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "code-integrity", "windows-only"])
            .with_short_description("Binaries should have Authenticode signatures.")
            .with_full_description(
                "Authenticode is Microsoft's code signing technology that helps verify the \
                 publisher identity and integrity of binaries. Signed binaries provide \
                 assurance that the code hasn't been tampered with since signing and comes \
                 from a trusted source. This is particularly important for software \
                 distribution and enterprise deployment scenarios.",
            )
            .with_fix_hint("Sign binary with Authenticode using signtool.exe")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' has an Authenticode signature.",
            )
            .with_message(
                "Warning_NoSignature",
                "'{0}' does not have an Authenticode signature. Consider signing the binary \
                 to verify its authenticity and integrity.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}': {2}.",
            );

        Self { descriptor }
    }

    /// Check if the PE has a certificate table (Authenticode signature)
    fn has_authenticode(pe: &PeBinary) -> bool {
        // Check for certificate table in data directories
        pe.has_certificate_table()
    }
}

impl Default for RequireAuthenticode {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for RequireAuthenticode {
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

        if Self::has_authenticode(pe) {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(
                context,
                FailureLevel::Warning,
                "Warning_NoSignature",
                &[&file_name],
            );
        }
    }
}
