//! AD2048: PeEnableStackVariableInitialization
//!
//! Verifies that stack variable initialization is enabled to prevent
//! information leakage from uninitialized stack memory for PE binaries.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, Binary, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{DwarfInfo, PeBinary};

use crate::rule_ids::AD2048;

pub struct PeEnableStackVariableInitialization {
    descriptor: RuleDescriptor,
}

impl PeEnableStackVariableInitialization {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2048, "PeEnableStackVariableInitialization")
            .with_category(RuleCategory::Security)
            .with_tags(&["hardening", "memory-safety", "windows-only"])
            .with_short_description(
                "Enable automatic stack variable initialization to prevent information leakage.",
            )
            .with_full_description(
                "Uninitialized stack variables can leak sensitive information from previous \
                 function calls or contain values that lead to undefined behavior when used. \
                 The '-ftrivial-auto-var-init' flag automatically initializes local variables \
                 to zero or a pattern. Use '-ftrivial-auto-var-init=zero' for zero initialization \
                 (most common) or '-ftrivial-auto-var-init=pattern' for a debugging pattern. \
                 This helps prevent information disclosure vulnerabilities and makes \
                 use-of-uninitialized-value bugs more deterministic. This rule checks for \
                 stack initialization flags in DWARF debug information for PE binaries built \
                 with MinGW/Clang.",
            )
            .with_fix_hint("Compile with -ftrivial-auto-var-init=zero (MinGW/Clang)")
            .with_default_level(FailureLevel::Note)
            .with_message(
                "Pass",
                "'{0}' has stack variable initialization enabled.",
            )
            .with_message(
                "Pass_Zero",
                "'{0}' has stack variable zero-initialization enabled (-ftrivial-auto-var-init=zero).",
            )
            .with_message(
                "Pass_Pattern",
                "'{0}' has stack variable pattern-initialization enabled (-ftrivial-auto-var-init=pattern).",
            )
            .with_message(
                "Note_NoInit",
                "'{0}' does not have automatic stack variable initialization enabled. \
                 Consider compiling with '-ftrivial-auto-var-init=zero' to prevent \
                 information leakage from uninitialized stack memory.",
            )
            .with_message(
                "NotApplicable_NoDwarf",
                "'{0}' does not contain DWARF debug information.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}': {2}.",
            );

        Self { descriptor }
    }

    /// Check DWARF for stack initialization flags
    fn check_dwarf_for_init(dwarf: &DwarfInfo) -> StackInitResult {
        if !dwarf.has_debug_info {
            return StackInitResult::Unknown;
        }

        for cu in &dwarf.compilation_units {
            let producer = &cu.compiler_info.producer;

            // Check for -ftrivial-auto-var-init=zero
            if producer.contains("-ftrivial-auto-var-init=zero")
                || producer.contains("trivial-auto-var-init=zero")
            {
                return StackInitResult::Zero;
            }

            // Check for -ftrivial-auto-var-init=pattern
            if producer.contains("-ftrivial-auto-var-init=pattern")
                || producer.contains("trivial-auto-var-init=pattern")
            {
                return StackInitResult::Pattern;
            }

            // Check individual flags
            for flag in &cu.parsed_info.flags {
                if flag.contains("trivial-auto-var-init=zero") {
                    return StackInitResult::Zero;
                }
                if flag.contains("trivial-auto-var-init=pattern") {
                    return StackInitResult::Pattern;
                }
            }
        }

        StackInitResult::NotEnabled
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StackInitResult {
    Zero,
    Pattern,
    NotEnabled,
    Unknown,
}

impl Default for PeEnableStackVariableInitialization {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for PeEnableStackVariableInitialization {
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

        // Try to load DWARF info
        let dwarf = match DwarfInfo::load(pe.path()) {
            Ok(d) if d.has_debug_info => d,
            _ => {
                self.log_not_applicable(context, "NotApplicable_NoDwarf", &[&file_name]);
                return;
            }
        };

        match Self::check_dwarf_for_init(&dwarf) {
            StackInitResult::Zero => {
                self.log_pass(context, "Pass_Zero", &[&file_name]);
            }
            StackInitResult::Pattern => {
                self.log_pass(context, "Pass_Pattern", &[&file_name]);
            }
            StackInitResult::NotEnabled | StackInitResult::Unknown => {
                self.log_fail(context, FailureLevel::Note, "Note_NoInit", &[&file_name]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_descriptor() {
        let rule = PeEnableStackVariableInitialization::new();
        assert_eq!(rule.descriptor().id, "AD2048");
        assert_eq!(rule.descriptor().name, "PeEnableStackVariableInitialization");
        assert_eq!(rule.descriptor().category, RuleCategory::Security);
    }
}
