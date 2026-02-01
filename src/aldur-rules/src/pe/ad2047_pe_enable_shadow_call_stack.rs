//! AD2047: PeEnableShadowCallStack
//!
//! Verifies Shadow Call Stack (SCS) is enabled for AArch64 PE binaries.
//! SCS provides strong return address protection by storing return addresses
//! in a separate shadow stack.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, Binary, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{DwarfInfo, PeBinary};

use crate::rule_ids::AD2047;

pub struct PeEnableShadowCallStack {
    descriptor: RuleDescriptor,
}

impl PeEnableShadowCallStack {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2047, "PeEnableShadowCallStack")
            .with_category(RuleCategory::Security)
            .with_tags(&["hardening", "control-flow", "windows-only", "arm-only"])
            .with_short_description(
                "Enable Shadow Call Stack (SCS) for AArch64 PE binaries to protect return addresses.",
            )
            .with_full_description(
                "Shadow Call Stack (SCS) is a security feature that protects return addresses \
                 by storing them in a separate 'shadow' stack. This prevents Return-Oriented \
                 Programming (ROP) attacks that rely on overwriting return addresses. SCS uses \
                 a dedicated register (x18 on AArch64) to point to the shadow stack. Enable with \
                 '-fsanitize=shadow-call-stack' when compiling with Clang. This rule checks for \
                 SCS flags in DWARF debug information for PE binaries built with MinGW/Clang.",
            )
            .with_fix_hint("Compile with -fsanitize=shadow-call-stack (AArch64 only)")
            .with_default_level(FailureLevel::Note)
            .with_message(
                "Pass",
                "'{0}' has Shadow Call Stack (SCS) enabled for return address protection.",
            )
            .with_message(
                "Pass_DwarfConfirmed",
                "'{0}' has Shadow Call Stack enabled (confirmed via DWARF debug info).",
            )
            .with_message(
                "Note_NoScs",
                "'{0}' does not have Shadow Call Stack (SCS) enabled. For AArch64 binaries \
                 built with Clang, consider compiling with '-fsanitize=shadow-call-stack' \
                 to protect return addresses from ROP attacks.",
            )
            .with_message(
                "NotApplicable_NotAArch64",
                "'{0}' is not an AArch64 binary. Shadow Call Stack is only available \
                 on AArch64 architecture.",
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

    /// Check DWARF for SCS flags
    fn check_dwarf_for_scs(dwarf: &DwarfInfo) -> (bool, bool) {
        let mut is_clang = false;
        let mut has_scs = false;

        for cu in &dwarf.compilation_units {
            // Check if compiled with Clang
            if cu.parsed_info.compiler_type == aldur_parsers::dwarf::CompilerType::Clang {
                is_clang = true;
            }

            // Check for SCS flags in producer or command line
            let producer = &cu.compiler_info.producer;
            if producer.contains("-fsanitize=shadow-call-stack")
                || producer.contains("sanitize=shadow-call-stack")
            {
                has_scs = true;
            }

            // Check individual flags
            for flag in &cu.parsed_info.flags {
                if flag.contains("sanitize=shadow-call-stack")
                    || flag == "-fsanitize=shadow-call-stack"
                {
                    has_scs = true;
                }
            }
        }

        (is_clang, has_scs)
    }
}

impl Default for PeEnableShadowCallStack {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for PeEnableShadowCallStack {
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

        // Check if this is an ARM64 binary
        if !pe.is_arm64() {
            self.log_not_applicable(context, "NotApplicable_NotAArch64", &[&file_name]);
            return;
        }

        // Try to load DWARF info
        let dwarf = match DwarfInfo::load(pe.path()) {
            Ok(d) if d.has_debug_info => d,
            _ => {
                self.log_not_applicable(context, "NotApplicable_NoDwarf", &[&file_name]);
                return;
            }
        };

        let (_is_clang, has_scs) = Self::check_dwarf_for_scs(&dwarf);

        if has_scs {
            self.log_pass(context, "Pass_DwarfConfirmed", &[&file_name]);
        } else {
            self.log_fail(context, FailureLevel::Note, "Note_NoScs", &[&file_name]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_descriptor() {
        let rule = PeEnableShadowCallStack::new();
        assert_eq!(rule.descriptor().id, "AD2047");
        assert_eq!(rule.descriptor().name, "PeEnableShadowCallStack");
        assert_eq!(rule.descriptor().category, RuleCategory::Security);
    }
}
