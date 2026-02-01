//! AD3033: RustEnableCET
//!
//! Verifies Rust binaries have Control-flow Enforcement Technology (CET) enabled.
//! For Rust, this is enabled with -Z cf-protection=full.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::ElfBinary;

use crate::rule_ids::AD3033;

pub struct RustEnableCET {
    descriptor: RuleDescriptor,
}

impl RustEnableCET {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD3033, "RustEnableCET")
            .with_category(RuleCategory::Security)
            .with_tags(&["nightly", "intel-only"])
            .with_short_description("Enable Intel CET for Rust binaries.")
            .with_full_description(
                "Rust binaries should be compiled with Intel Control-flow Enforcement \
                 Technology (CET) enabled. CET provides hardware-based protection against \
                 control-flow hijacking attacks like ROP and JOP. For Rust, enable CET \
                 using the unstable flag '-Z cf-protection=full'. This requires a nightly \
                 Rust compiler and a processor that supports CET.",
            )
            .with_fix_hint("Use RUSTFLAGS='-Z cf-protection=full' (nightly only)")
            .with_default_level(FailureLevel::Note)
            .with_message(
                "Pass",
                "'{0}' is a Rust binary with Intel CET enabled.",
            )
            .with_message(
                "Pass_IBT",
                "'{0}' is a Rust binary with Intel CET IBT (Indirect Branch Tracking) enabled.",
            )
            .with_message(
                "Pass_SHSTK",
                "'{0}' is a Rust binary with Intel CET Shadow Stack enabled.",
            )
            .with_message(
                "Note_NoCET",
                "'{0}' is a Rust binary that does not have Intel CET enabled. CET requires \
                 nightly Rust with '-Z cf-protection=full'. This is informational since \
                 CET is not available on stable Rust.",
            )
            .with_message(
                "Warning_PartialCET",
                "'{0}' is a Rust binary with only partial CET protection. Consider \
                 enabling both IBT and Shadow Stack with '-Z cf-protection=full'.",
            )
            .with_message(
                "NotApplicable_NotRust",
                "'{0}' is not a Rust binary.",
            )
            .with_message(
                "NotApplicable_NotX86",
                "'{0}' is not an x86_64 binary. Intel CET is only available on x86_64.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for RustEnableCET {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for RustEnableCET {
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

        // CET is x86_64 only
        if !elf.is_x86_64() {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Not an x86_64 binary".to_string()),
            );
        }

        // Only applicable to Rust binaries
        if !elf.is_rust_binary {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Not a Rust binary".to_string()),
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

        // Verify it's a Rust binary
        if !elf.is_rust_binary {
            self.log_not_applicable(context, "NotApplicable_NotRust", &[&file_name]);
            return;
        }

        // Verify it's x86_64
        if !elf.is_x86_64() {
            self.log_not_applicable(context, "NotApplicable_NotX86", &[&file_name]);
            return;
        }

        let has_ibt = elf.has_intel_cet_ibt();
        let has_shstk = elf.has_intel_cet_shstk();

        if has_ibt && has_shstk {
            self.log_pass(context, "Pass", &[&file_name]);
        } else if has_ibt || has_shstk {
            self.log_fail(
                context,
                FailureLevel::Note,
                "Warning_PartialCET",
                &[&file_name],
            );
        } else {
            self.log_fail(
                context,
                FailureLevel::Note,
                "Note_NoCET",
                &[&file_name],
            );
        }
    }
}
