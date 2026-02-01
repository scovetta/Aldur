//! AD3018: EnableArmPAC
//!
//! Checks that AArch64 binaries have ARM Pointer Authentication Code (PAC) enabled.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::ElfBinary;

use crate::rule_ids::AD3018;

pub struct EnableArmPAC {
    descriptor: RuleDescriptor,
}

impl EnableArmPAC {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD3018, "EnableArmPAC")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "control-flow", "arm-only", "android-cdd", "openssf"])
            .with_short_description("Enable ARM Pointer Authentication Code (PAC).")
            .with_full_description(
                "ARM Pointer Authentication Code (PAC) provides hardware-based protection \
                 against Return-Oriented Programming (ROP) attacks. PAC signs return addresses \
                 and function pointers with a cryptographic signature that is verified before \
                 use. Compile with '-mbranch-protection=standard' (GCC 9+, Clang 8+) to enable PAC.",
            )
            .with_fix_hint("Compile with -mbranch-protection=standard")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' has ARM PAC enabled.",
            )
            .with_message(
                "Warning",
                "'{0}' does not have ARM PAC enabled. Compile with \
                 '-mbranch-protection=standard' to enable hardware-based ROP protection.",
            )
            .with_message(
                "NotApplicable_NotAArch64",
                "'{0}' is not an AArch64 binary. ARM PAC only applies to AArch64.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for EnableArmPAC {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableArmPAC {
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

        if !elf.is_aarch64() {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Not an AArch64 binary".to_string()),
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

        if !elf.is_aarch64() {
            self.log_not_applicable(context, "NotApplicable_NotAArch64", &[&file_name]);
            return;
        }

        if elf.has_arm_pac() {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(context, FailureLevel::Warning, "Warning", &[&file_name]);
        }
    }
}
