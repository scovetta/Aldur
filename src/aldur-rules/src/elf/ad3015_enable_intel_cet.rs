//! AD3015: EnableIntelCET
//!
//! Checks that x86-64 binaries have Intel Control-flow Enforcement Technology (CET)
//! enabled, specifically Indirect Branch Tracking (IBT).
//! Note: This rule is for GCC/Clang binaries. Rust binaries are handled by AD3033.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::ElfBinary;

use crate::elf::compiler_utils::{check_compiler_support, detect_compiler, CompilerFeature};
use crate::rule_ids::AD3015;

pub struct EnableIntelCET {
    descriptor: RuleDescriptor,
}

impl EnableIntelCET {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD3015, "EnableIntelCET")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "control-flow", "intel-only", "rhel-annocheck", "openssf"])
            .with_short_description("Enable Intel Control-flow Enforcement Technology (CET).")
            .with_full_description(
                "Intel CET provides hardware-based protection against Return-Oriented \
                 Programming (ROP) and Jump-Oriented Programming (JOP) attacks. IBT (Indirect \
                 Branch Tracking) ensures indirect branches land on ENDBR instructions. \
                 Compile with '-fcf-protection=full' (GCC 8+, Clang 7+) to enable CET.",
            )
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' has Intel CET (IBT) enabled.",
            )
            .with_message(
                "Warning",
                "'{0}' does not have Intel CET enabled. Compile with '-fcf-protection=full' \
                 to enable hardware-based control-flow protection.",
            )
            .with_message(
                "NotApplicable_NotX86_64",
                "'{0}' is not an x86-64 binary. Intel CET only applies to x86-64.",
            )
            .with_message(
                "NotApplicable_RustBinary",
                "'{0}' is a Rust binary. See AD3033 (RustEnableCET) for Rust-specific CET checking.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            )
            .with_fix_hint("Compile with -fcf-protection=full (GCC 8+, Clang 7+).");

        Self { descriptor }
    }
}

impl Default for EnableIntelCET {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableIntelCET {
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

        // Only applicable to x86-64
        if !elf.is_x86_64() {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Not an x86-64 binary".to_string()),
            );
        }

        // Skip Rust binaries - they have their own rule (AD3033)
        let compiler = detect_compiler(elf);
        if let Some(reason) = check_compiler_support(&compiler, CompilerFeature::IntelCET) {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some(reason),
            );
        }

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

        if !elf.is_x86_64() {
            self.log_not_applicable(context, "NotApplicable_NotX86_64", &[&file_name]);
            return;
        }

        if elf.has_intel_cet_ibt() {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(context, FailureLevel::Warning, "Warning", &[&file_name]);
        }
    }
}
