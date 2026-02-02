//! AD3019: EnableLTO
//!
//! Checks that binaries are compiled with Link-Time Optimization (LTO).
//! LTO enables cross-module optimizations and can improve security.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{DwarfInfo, ElfBinary};

use crate::rule_ids::AD3019;

pub struct EnableLTO {
    descriptor: RuleDescriptor,
}

impl EnableLTO {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD3019, "EnableLTO")
            .with_category(RuleCategory::Performance)
            .with_tags(&["recommended", "linux-only"])
            .with_short_description("Enable Link-Time Optimization (LTO).")
            .with_full_description(
                "Link-Time Optimization (LTO) enables the compiler to perform optimizations \
                 across all compilation units at link time. This can improve performance and \
                 enable security optimizations that wouldn't be possible otherwise. LTO also \
                 enables better dead code elimination and can reduce attack surface. \
                 Compile with '-flto' to enable.",
            )
            .with_fix_hint("Compile with -flto")
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
                "NotApplicable_NoDebugInfo",
                "'{0}' does not contain debug information to determine LTO usage.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}': {2}.",
            );

        Self { descriptor }
    }

    fn check_lto(elf: &ElfBinary) -> Option<bool> {
        // First try DWARF info
        if let Ok(dwarf_info) = DwarfInfo::parse(elf.data())
            && dwarf_info.has_debug_info
        {
            return Some(dwarf_info.has_lto());
        }

        // Fallback: check for LTO-related sections or symbols
        // LTO binaries often have .gnu.lto_ sections or specific symbols
        // This is a heuristic when DWARF isn't available
        None
    }
}

impl Default for EnableLTO {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableLTO {
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

        match Self::check_lto(elf) {
            Some(true) => {
                self.log_pass(context, "Pass", &[&file_name]);
            }
            Some(false) => {
                self.log_fail(context, FailureLevel::Note, "Note", &[&file_name]);
            }
            None => {
                self.log_not_applicable(context, "NotApplicable_NoDebugInfo", &[&file_name]);
            }
        }
    }
}
