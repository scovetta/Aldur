//! AD3014: NoTextRelocations
//!
//! Checks that binaries do not have text relocations (DT_TEXTREL).
//! Text relocations require the code section to be writable, which
//! violates W^X (Write XOR Execute) security principle.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::ElfBinary;

use crate::rule_ids::AD3014;

pub struct NoTextRelocations {
    descriptor: RuleDescriptor,
}

impl NoTextRelocations {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD3014, "NoTextRelocations")
            .with_category(RuleCategory::Correctness)
            .with_tags(&[
                "critical",
                "memory-safety",
                "linux-only",
                "android-cdd",
                "rhel-annocheck",
                "openssf",
            ])
            .with_short_description("Do not use text relocations (DT_TEXTREL).")
            .with_full_description(
                "Text relocations (DT_TEXTREL) require the code section to be writable at \
                 runtime, which violates the W^X (Write XOR Execute) security principle. \
                 This makes exploitation easier by allowing code modification. Compile with \
                 -fPIC or -fPIE to generate position-independent code that doesn't require \
                 text relocations.",
            )
            .with_fix_hint("Compile with -fPIC or -fPIE")
            .with_default_level(FailureLevel::Error)
            .with_message("Pass", "'{0}' does not have text relocations.")
            .with_message(
                "Error",
                "'{0}' has text relocations (DT_TEXTREL), requiring writable code sections. \
                 Compile with -fPIC or -fPIE to eliminate text relocations.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for NoTextRelocations {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for NoTextRelocations {
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

        let elf = match binary.as_ref().as_any().downcast_ref::<ElfBinary>() {
            Some(elf) => elf,
            None => {
                return (
                    AnalysisApplicability::NotApplicableToSpecifiedTarget,
                    Some("Could not access ELF data".to_string()),
                );
            }
        };

        use aldur_parsers::elf::ElfType;

        match elf.elf_type {
            ElfType::Core | ElfType::None | ElfType::Relocatable => {
                return (
                    AnalysisApplicability::NotApplicableToSpecifiedTarget,
                    Some("ELF is core, none, or relocatable".to_string()),
                );
            }
            _ => {}
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

        if elf.has_textrel {
            self.log_fail(context, FailureLevel::Error, "Error", &[&file_name]);
        } else {
            self.log_pass(context, "Pass", &[&file_name]);
        }
    }
}
