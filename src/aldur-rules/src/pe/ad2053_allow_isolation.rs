//! AD2053: AllowIsolation
//!
//! Checks that PE binaries allow isolation (NO_ISOLATION flag is NOT set).
//! Isolation allows the Windows loader to properly apply application manifests.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::PeBinary;

use crate::rule_ids::AD2053;

pub struct AllowIsolation {
    descriptor: RuleDescriptor,
}

impl AllowIsolation {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2053, "AllowIsolation")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "windows-only"])
            .with_short_description("Binaries should allow isolation for proper manifest handling.")
            .with_full_description(
                "The /ALLOWISOLATION linker option enables manifest-based isolation for \
                 Windows applications. When NO_ISOLATION is set, the Windows loader ignores \
                 the application's manifest, which can prevent proper side-by-side assembly \
                 loading, User Account Control (UAC) manifest settings, and other manifest-based \
                 features. Unless there is a specific reason to disable isolation, binaries \
                 should allow it for proper Windows integration and security features.",
            )
            .with_fix_hint("Remove /ALLOWISOLATION:NO linker option")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' allows isolation (manifest processing is enabled).",
            )
            .with_message(
                "Warning_NoIsolation",
                "'{0}' has the NO_ISOLATION flag set, which disables manifest processing. \
                 Consider removing /NXCOMPAT:NO from linker options unless isolation must \
                 be disabled for compatibility reasons.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}': {2}.",
            );

        Self { descriptor }
    }
}

impl Default for AllowIsolation {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for AllowIsolation {
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

        if pe.allows_isolation() {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(
                context,
                FailureLevel::Warning,
                "Warning_NoIsolation",
                &[&file_name],
            );
        }
    }
}
