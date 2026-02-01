//! AD5011: RequireCodeSignature
//!
//! Checks that Mach-O binaries have a code signature.
//! Code signing is required for execution on iOS and recommended on macOS.
//! With Hardened Runtime, it provides additional security guarantees.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::MachOBinary;

use crate::rule_ids::AD5011;

pub struct RequireCodeSignature {
    descriptor: RuleDescriptor,
}

impl RequireCodeSignature {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD5011, "RequireCodeSignature")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "code-integrity", "macos-only"])
            .with_short_description("Require code signature on Mach-O binaries.")
            .with_full_description(
                "Code signing provides integrity verification and is required on iOS. On macOS, \
                 code signing enables Hardened Runtime, Library Validation, and other security \
                 features. Unsigned binaries cannot use modern security features and may be \
                 blocked by Gatekeeper. Sign your binaries with 'codesign' or through Xcode.",
            )
            .with_fix_hint("Sign binary with codesign or Xcode")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' has a code signature.",
            )
            .with_message(
                "Warning",
                "'{0}' does not have a code signature. Code signing is required on iOS and \
                 recommended on macOS. Sign with 'codesign -s \"Developer ID\" binary'.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for RequireCodeSignature {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for RequireCodeSignature {
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

        if macho.has_code_signature {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(context, FailureLevel::Warning, "Warning", &[&file_name]);
        }
    }
}
