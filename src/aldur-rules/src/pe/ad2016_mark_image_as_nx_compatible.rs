//! AD2016: MarkImageAsNXCompatible
//!
//! Binaries should be marked as NX compatible to help prevent execution
//! of untrusted data as code.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::PeBinary;

use crate::rule_ids::AD2016;

pub struct MarkImageAsNXCompatible {
    descriptor: RuleDescriptor,
}

impl MarkImageAsNXCompatible {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2016, "MarkImageAsNXCompatible")
            .with_category(RuleCategory::Security)
            .with_tags(&["critical", "memory-safety", "windows-only", "openssf"])
            .with_short_description("Binaries should be marked as NX compatible (DEP enabled).")
            .with_full_description(
                "Binaries should be marked as NX compatible to help prevent execution of \
                 untrusted data as code. The NXCompat bit, also known as \"Data Execution \
                 Prevention\" (DEP) or \"Execute Disable\" (XD), triggers a processor security \
                 feature that allows a program to mark a piece of memory as non-executable. \
                 This helps mitigate memory corruption vulnerabilities by preventing an attacker \
                 from supplying direct shellcode in their exploit.",
            )
            .with_fix_hint("Link with /NXCOMPAT")
            .with_default_level(FailureLevel::Error)
            .with_message(
                "Pass",
                "'{0}' is marked as NX compatible, helping to prevent attackers from executing \
                 code that is injected into data segments.",
            )
            .with_message(
                "Error",
                "'{0}' is not marked NX compatible. The NXCompat bit, also known as \"Data \
                 Execution Prevention\" (DEP) or \"Execute Disable\" (XD), is a processor \
                 feature that allows a program to mark a piece of memory as non-executable. \
                 To resolve this issue, don't set /NXCOMPAT:NO on link.exe command line.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for MarkImageAsNXCompatible {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for MarkImageAsNXCompatible {
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

        if pe.is_nx_compat() {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(context, FailureLevel::Error, "Error", &[&file_name]);
        }
    }
}
