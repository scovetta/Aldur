//! AD3011: EnableBindNow
//!
//! Check that BIND_NOW is enabled for full RELRO protection.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::ElfBinary;

use crate::rule_ids::AD3011;

pub struct EnableBindNow {
    descriptor: RuleDescriptor,
}

impl EnableBindNow {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD3011, "EnableBindNow")
            .with_category(RuleCategory::Security)
            .with_tags(&[
                "critical",
                "memory-safety",
                "android-cdd",
                "rhel-annocheck",
                "openssf",
            ])
            .with_short_description("Enable BIND_NOW for full RELRO protection.")
            .with_full_description(
                "This check ensures that some relocation data is marked as read only after the \
                 executable is loaded, and moved below the '.data' section in memory. This \
                 prevents them from being overwritten, which can redirect control flow. Use the \
                 compiler flags '-Wl,-z,now' to enable this.",
            )
            .with_fix_hint("Link with -Wl,-z,now")
            .with_default_level(FailureLevel::Error)
            .with_message(
                "Pass",
                "The BIND_NOW flag was present, so '{0}' is protected.",
            )
            .with_message(
                "Error",
                "The BIND_NOW flag is missing from this binary, so relocation sections in '{0}' \
                 will not be marked as read only after the binary is loaded. An attacker can \
                 overwrite these to redirect control flow. Ensure you are compiling with the \
                 compiler flags '-Wl,-z,now' to address this.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for EnableBindNow {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableBindNow {
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

        if binary.format() != BinaryFormat::ELF {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Not an ELF binary".to_string()),
            );
        }

        // Skip object files - linker flags are not applicable
        let elf = match binary.as_ref().as_any().downcast_ref::<ElfBinary>() {
            Some(elf) => elf,
            None => {
                return (
                    AnalysisApplicability::NotApplicableToSpecifiedTarget,
                    Some("Could not access ELF data".to_string()),
                );
            }
        };

        if elf.is_object_file() {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Object files do not have linker-level protections".to_string()),
            );
        }

        (AnalysisApplicability::ApplicableToSpecifiedTarget, None)
    }

    fn analyze(&self, context: &mut AnalysisContext) {
        let file_name = context.file_name();
        let binary = context.binary().expect("Binary must be loaded").clone();

        let elf = match binary.as_ref().as_any().downcast_ref::<ElfBinary>() {
            Some(elf) => elf,
            None => {
                self.log_not_applicable(
                    context,
                    "NotApplicable_InvalidMetadata",
                    &[&file_name, self.name(), "Could not access ELF data"],
                );
                return;
            }
        };

        if elf.has_bind_now {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(context, FailureLevel::Error, "Error", &[&file_name]);
        }
    }
}
