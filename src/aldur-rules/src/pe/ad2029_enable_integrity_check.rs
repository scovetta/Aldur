//! AD2029: EnableIntegrityCheck
//!
//! Binaries that are loaded by certain Windows features must opt into
//! Windows validation of their digital signatures by setting /INTEGRITYCHECK.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::PeBinary;

use crate::rule_ids::AD2029;

pub struct EnableIntegrityCheck {
    descriptor: RuleDescriptor,
}

impl EnableIntegrityCheck {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2029, "EnableIntegrityCheck")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "code-integrity", "windows-only"])
            .with_short_description(
                "Binaries should enable /INTEGRITYCHECK for digital signature validation.",
            )
            .with_full_description(
                "Binaries that are loaded by certain Windows features must (and device drivers \
                 should) opt into Windows validation of their digital signatures by setting the \
                 /INTEGRITYCHECK linker flag. This option sets the \
                 IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY attribute in the PE header which tells \
                 the memory manager to validate a binary's digital signature when loaded. Any \
                 user mode code that is interfacing with Early Launch Antimalware (ELAM) drivers, \
                 integrates with device firmware execution or is trying to load into protected \
                 process lite space must enable /INTEGRITYCHECK.",
            )
            .with_fix_hint("Link with /INTEGRITYCHECK")
            .with_default_level(FailureLevel::Error)
            .with_message(
                "Pass",
                "'{0}' was compiled with /INTEGRITYCHECK and will therefore have its digital \
                 signature validated at load time when executing in sensitive Windows runtime \
                 environments.",
            )
            .with_message(
                "Error",
                "'{0}' was not compiled with /INTEGRITYCHECK and therefore will not have its \
                 digital signature validated at load time. Failing to validate binary signatures \
                 increases the risk of loading malicious code in low-level, high-privilege \
                 execution environments.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for EnableIntegrityCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableIntegrityCheck {
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

        if pe.has_force_integrity() {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(context, FailureLevel::Error, "Error", &[&file_name]);
        }
    }
}
