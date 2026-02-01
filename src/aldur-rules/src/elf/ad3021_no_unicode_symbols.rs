//! AD3021: NoUnicodeSymbols
//!
//! Checks that binaries do not contain Unicode symbols which could be
//! used for obfuscation or "Trojan Source" style attacks.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::ElfBinary;

use crate::rule_ids::AD3021;

pub struct NoUnicodeSymbols {
    descriptor: RuleDescriptor,
}

impl NoUnicodeSymbols {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD3021, "NoUnicodeSymbols")
            .with_category(RuleCategory::Correctness)
            .with_tags(&["recommended", "code-integrity", "linux-only"])
            .with_short_description("Do not use Unicode characters in symbol names.")
            .with_full_description(
                "Symbol names should only contain ASCII characters. Unicode characters in \
                 symbol names can be used for obfuscation, making code review difficult and \
                 potentially hiding malicious functionality. This is related to 'Trojan Source' \
                 style attacks where visually similar Unicode characters are used to disguise \
                 malicious code.",
            )
            .with_fix_hint("Remove Unicode characters from symbol names; use ASCII only")
            .with_default_level(FailureLevel::Warning)
            .with_message("Pass", "'{0}' does not contain Unicode symbol names.")
            .with_message(
                "Warning",
                "'{0}' contains {1} symbol(s) with non-ASCII characters: {2}. \
                 This may indicate obfuscation attempts.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}': {2}.",
            );

        Self { descriptor }
    }
}

impl Default for NoUnicodeSymbols {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for NoUnicodeSymbols {
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
            ElfType::Core | ElfType::None => {
                return (
                    AnalysisApplicability::NotApplicableToSpecifiedTarget,
                    Some("ELF is core or none".to_string()),
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

        let unicode_symbols = elf.find_unicode_symbols();

        if unicode_symbols.is_empty() {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            let count = unicode_symbols.len().to_string();
            // Limit the number of symbols shown to avoid very long messages
            let examples: String = unicode_symbols
                .iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            let examples = if unicode_symbols.len() > 5 {
                format!("{} (and {} more)", examples, unicode_symbols.len() - 5)
            } else {
                examples
            };

            self.log_fail(
                context,
                FailureLevel::Warning,
                "Warning",
                &[&file_name, &count, &examples],
            );
        }
    }
}
