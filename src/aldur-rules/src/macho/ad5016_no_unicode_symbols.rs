//! AD5016: NoUnicodeSymbolsMachO
//!
//! Checks that Mach-O binaries do not contain non-ASCII symbols which could
//! be used for homograph attacks or obfuscation.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::MachOBinary;

use crate::rule_ids::AD5016;

pub struct NoUnicodeSymbolsMachO {
    descriptor: RuleDescriptor,
}

impl NoUnicodeSymbolsMachO {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD5016, "NoUnicodeSymbolsMachO")
            .with_category(RuleCategory::Correctness)
            .with_tags(&["recommended", "code-integrity", "macos-only"])
            .with_short_description("Do not use non-ASCII characters in symbol names.")
            .with_full_description(
                "Symbol names containing non-ASCII characters (Unicode) can be used for \
                 homograph attacks, where a malicious symbol appears identical to a legitimate \
                 one. For example, using Cyrillic 'а' instead of ASCII 'a'. This can hide \
                 malicious code or confuse analysis tools.",
            )
            .with_fix_hint("Remove Unicode characters from symbol names; use ASCII only")
            .with_default_level(FailureLevel::Warning)
            .with_message("Pass", "'{0}' does not contain non-ASCII symbol names.")
            .with_message(
                "Warning",
                "'{0}' contains {1} symbol(s) with non-ASCII characters. This could indicate \
                 obfuscation or homograph attacks: {2}",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for NoUnicodeSymbolsMachO {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for NoUnicodeSymbolsMachO {
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

        if binary.format() != BinaryFormat::MachO {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Not a Mach-O binary".to_string()),
            );
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

        // Get all symbol names and filter for non-ASCII
        let all_symbols = macho.get_all_symbol_names();
        let unicode_symbols: Vec<&String> = all_symbols.iter().filter(|s| !s.is_ascii()).collect();

        if unicode_symbols.is_empty() {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            let count = unicode_symbols.len().to_string();
            let sample: String = unicode_symbols
                .iter()
                .take(5)
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let sample_str = if unicode_symbols.len() > 5 {
                format!("{}...", sample)
            } else {
                sample
            };
            self.log_fail(
                context,
                FailureLevel::Warning,
                "Warning",
                &[&file_name, &count, &sample_str],
            );
        }
    }
}
