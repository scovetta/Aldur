//! AD5017: EnableLTOMachO
//!
//! Checks that Mach-O binaries are compiled with Link-Time Optimization (LTO).
//! LTO enables additional security optimizations across compilation units.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{DwarfInfo, MachOBinary};

use crate::rule_ids::AD5017;

pub struct EnableLTOMachO {
    descriptor: RuleDescriptor,
}

impl EnableLTOMachO {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD5017, "EnableLTOMachO")
            .with_category(RuleCategory::Performance)
            .with_tags(&["recommended", "macos-only"])
            .with_short_description("Enable Link-Time Optimization (LTO).")
            .with_full_description(
                "Link-Time Optimization (LTO) performs optimization across all compilation \
                 units at link time. This enables additional security-relevant optimizations \
                 like whole-program devirtualization and more aggressive inlining that can \
                 reduce attack surface. Enable with '-flto' compiler flag.",
            )
            .with_fix_hint("Compile with -flto")
            .with_default_level(FailureLevel::Note)
            .with_message("Pass", "'{0}' was compiled with Link-Time Optimization.")
            .with_message(
                "Note",
                "'{0}' was not compiled with LTO. Consider using '-flto' for additional \
                 optimizations and potential security benefits.",
            )
            .with_message(
                "NotApplicable_NoDebugInfo",
                "'{0}' does not contain debug information to determine LTO usage.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for EnableLTOMachO {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableLTOMachO {
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

        // Try to parse DWARF info to check for LTO
        let dwarf_info = match DwarfInfo::parse(macho.data()) {
            Ok(info) => info,
            Err(_) => {
                self.log_not_applicable(context, "NotApplicable_NoDebugInfo", &[&file_name]);
                return;
            }
        };

        if dwarf_info.compilation_units.is_empty() {
            self.log_not_applicable(context, "NotApplicable_NoDebugInfo", &[&file_name]);
            return;
        }

        // Check if LTO was used
        if dwarf_info.has_lto() {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(context, FailureLevel::Note, "Note", &[&file_name]);
        }
    }
}
