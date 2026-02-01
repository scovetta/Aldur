//! AD2037: PeEnableStackClashProtection
//!
//! Checks for stack clash protection in PE binaries with DWARF debug info.
//! Stack clash protection prevents the stack from clashing with other memory regions.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, Binary, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{DwarfInfo, PeBinary};

use crate::rule_ids::AD2037;

pub struct PeEnableStackClashProtection {
    descriptor: RuleDescriptor,
}

impl PeEnableStackClashProtection {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2037, "PeEnableStackClashProtection")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "memory-safety", "windows-only", "openssf"])
            .with_short_description(
                "Enable stack clash protection for PE binaries built with MinGW/Clang.",
            )
            .with_full_description(
                "PE binaries built with MinGW or Clang should enable stack clash protection \
                 to prevent the stack from 'clashing' with other memory regions (like the heap). \
                 Stack clash protection works by probing stack pages as they are allocated, \
                 preventing attackers from using large stack allocations to skip over guard pages. \
                 Compile with '-fstack-clash-protection' to enable. This rule checks for the \
                 presence of the -fstack-clash-protection flag in DWARF debug information.",
            )
            .with_fix_hint("Compile with -fstack-clash-protection (MinGW/Clang)")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' was compiled with stack clash protection enabled.",
            )
            .with_message(
                "Pass_DwarfConfirmed",
                "'{0}' has stack clash protection enabled (confirmed via DWARF debug info).",
            )
            .with_message(
                "Warning",
                "'{0}' was not compiled with stack clash protection. Consider using \
                 '-fstack-clash-protection' for improved security against stack clash attacks.",
            )
            .with_message(
                "Warning_ExplicitlyDisabled",
                "'{0}' was compiled with stack clash protection explicitly disabled \
                 (-fno-stack-clash-protection). Consider removing this flag for improved security.",
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

    /// Check for stack clash protection in DWARF info
    fn check_stack_clash_protection(dwarf: &DwarfInfo) -> StackClashResult {
        if !dwarf.has_debug_info {
            return StackClashResult::NoDwarf;
        }

        // Check if -fstack-clash-protection flag is present
        let has_protection = dwarf.has_flag("-fstack-clash-protection");
        let explicitly_disabled = dwarf.has_flag("-fno-stack-clash-protection");

        if explicitly_disabled {
            return StackClashResult::ExplicitlyDisabled;
        }

        if has_protection {
            return StackClashResult::Enabled;
        }

        // Also check producer strings directly
        for cu in &dwarf.compilation_units {
            let producer = &cu.compiler_info.producer;

            if producer.contains("-fstack-clash-protection")
                && !producer.contains("-fno-stack-clash-protection")
            {
                return StackClashResult::Enabled;
            }

            if producer.contains("-fno-stack-clash-protection") {
                return StackClashResult::ExplicitlyDisabled;
            }

            if producer.contains("stack-clash-protection")
                && !producer.contains("no-stack-clash-protection")
            {
                return StackClashResult::Enabled;
            }
        }

        StackClashResult::Disabled
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StackClashResult {
    Enabled,
    Disabled,
    ExplicitlyDisabled,
    NoDwarf,
}

impl Default for PeEnableStackClashProtection {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for PeEnableStackClashProtection {
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
            Ok(d) if d.has_debug_info => d,
            _ => {
                self.log_not_applicable(context, "NotApplicable_NoDwarf", &[&file_name]);
                return;
            }
        };

        // Check DWARF producer strings for stack clash protection flags
        match Self::check_stack_clash_protection(&dwarf) {
            StackClashResult::Enabled => {
                self.log_pass(context, "Pass_DwarfConfirmed", &[&file_name]);
            }
            StackClashResult::Disabled => {
                self.log_fail(context, FailureLevel::Warning, "Warning", &[&file_name]);
            }
            StackClashResult::ExplicitlyDisabled => {
                self.log_fail(
                    context,
                    FailureLevel::Warning,
                    "Warning_ExplicitlyDisabled",
                    &[&file_name],
                );
            }
            StackClashResult::NoDwarf => {
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
        let rule = PeEnableStackClashProtection::new();
        assert_eq!(rule.descriptor().id, "AD2037");
        assert_eq!(rule.descriptor().name, "PeEnableStackClashProtection");
        assert_eq!(rule.descriptor().category, RuleCategory::Security);
    }
}
