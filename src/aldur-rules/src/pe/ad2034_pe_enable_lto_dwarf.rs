//! AD2034: PeEnableLtoDwarf
//!
//! Checks for Link-Time Optimization (LTO) in PE binaries with DWARF debug info.
//! Verifies that -flto flag is present in DWARF producer strings.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, Binary, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{DwarfInfo, PeBinary};

use crate::rule_ids::AD2034;

pub struct PeEnableLtoDwarf {
    descriptor: RuleDescriptor,
}

impl PeEnableLtoDwarf {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2034, "PeEnableLtoDwarf")
            .with_category(RuleCategory::Performance)
            .with_tags(&["recommended", "windows-only"])
            .with_short_description(
                "Enable Link-Time Optimization for PE binaries built with MinGW/Clang.",
            )
            .with_full_description(
                "Link-Time Optimization (LTO) enables the compiler to perform optimizations \
                 across all compilation units at link time. This can improve performance and \
                 enable security optimizations that wouldn't be possible otherwise. LTO also \
                 enables better dead code elimination which can reduce attack surface. \
                 Compile with '-flto' to enable. This rule checks for the presence of LTO \
                 flags in DWARF debug information for PE binaries built with MinGW or Clang.",
            )
            .with_fix_hint("Compile with -flto (MinGW/Clang)")
            .with_default_level(FailureLevel::Note)
            .with_message(
                "Pass",
                "'{0}' was compiled with Link-Time Optimization (LTO).",
            )
            .with_message(
                "Note",
                "'{0}' was not compiled with Link-Time Optimization. Consider using '-flto' \
                 for improved optimization and potential security benefits.",
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

    /// Check for LTO in DWARF info
    fn check_lto(dwarf: &DwarfInfo) -> LtoResult {
        if !dwarf.has_debug_info {
            return LtoResult::NoDwarf;
        }

        // Use the built-in DWARF helper to check for LTO
        if dwarf.has_lto() {
            return LtoResult::Enabled;
        }

        // Additional check for -flto flags in producer strings
        for cu in &dwarf.compilation_units {
            let producer = &cu.compiler_info.producer;

            // Check for various LTO flags
            if producer.contains("-flto")
                || producer.contains("-flto=thin")
                || producer.contains("-flto=full")
                || producer.contains("LTO")
            {
                return LtoResult::Enabled;
            }
        }

        LtoResult::Disabled
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LtoResult {
    Enabled,
    Disabled,
    NoDwarf,
}

impl Default for PeEnableLtoDwarf {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for PeEnableLtoDwarf {
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

        let pe = match binary.as_ref().as_any().downcast_ref::<PeBinary>() {
            Some(pe) => pe,
            None => {
                return (
                    AnalysisApplicability::NotApplicableToSpecifiedTarget,
                    Some("Could not access PE data".to_string()),
                );
            }
        };

        // Only applicable to PE binaries with DWARF debug info (MinGW/Clang builds)
        if !pe.has_dwarf_debug_info() {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("PE binary does not have DWARF debug info".to_string()),
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
            Ok(d) => d,
            Err(_) => {
                self.log_not_applicable(context, "NotApplicable_NoDwarf", &[&file_name]);
                return;
            }
        };

        // Check DWARF producer strings for LTO flags
        match Self::check_lto(&dwarf) {
            LtoResult::Enabled => {
                self.log_pass(context, "Pass", &[&file_name]);
            }
            LtoResult::Disabled => {
                self.log_fail(context, FailureLevel::Note, "Note", &[&file_name]);
            }
            LtoResult::NoDwarf => {
                self.log_not_applicable(context, "NotApplicable_NoDwarf", &[&file_name]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_descriptor() {
        let rule = PeEnableLtoDwarf::new();
        assert_eq!(rule.descriptor().id, "AD2034");
        assert_eq!(rule.descriptor().name, "PeEnableLtoDwarf");
        assert_eq!(rule.descriptor().category, RuleCategory::Performance);
    }
}
