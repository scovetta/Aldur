//! AD5031: CheckNotEncrypted
//!
//! Checks if a Mach-O binary is encrypted (App Store encryption).
//! This is informational - encrypted binaries cannot be analyzed for security features.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::MachOBinary;

use crate::rule_ids::AD5031;

pub struct CheckNotEncrypted {
    descriptor: RuleDescriptor,
}

impl CheckNotEncrypted {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD5031, "CheckNotEncrypted")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "macos-only"])
            .with_short_description("Check if Mach-O binary is encrypted.")
            .with_full_description(
                "iOS apps distributed through the App Store are encrypted using FairPlay DRM. \
                 Encrypted binaries cannot be fully analyzed for security features since \
                 the code sections are not readable. This check reports whether a binary \
                 has the LC_ENCRYPTION_INFO load command indicating encryption. Note that \
                 for analysis purposes, you may need to decrypt the binary first using \
                 appropriate tools on a jailbroken device.",
            )
            .with_fix_hint("Informational - decryption required for analysis")
            .with_default_level(FailureLevel::Note)
            .with_message(
                "Pass",
                "'{0}' is not encrypted and can be fully analyzed.",
            )
            .with_message(
                "Note_Encrypted",
                "'{0}' is encrypted (FairPlay DRM). Some security analysis may be limited. \
                 Consider analyzing the unencrypted version for complete security assessment.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for CheckNotEncrypted {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for CheckNotEncrypted {
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

        // Skip object files, core dumps, and dsym bundles
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

        if !macho.is_encrypted {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(
                context,
                FailureLevel::Note,
                "Note_Encrypted",
                &[&file_name],
            );
        }
    }
}
