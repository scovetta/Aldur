//! AD3001: EnablePositionIndependentExecutable
//!
//! A Position Independent Executable (PIE) relocates all of its sections at
//! load time if ASLR is enabled. This makes ROP-style attacks more difficult.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::ElfBinary;

use crate::rule_ids::AD3001;

pub struct EnablePositionIndependentExecutable {
    descriptor: RuleDescriptor,
}

impl EnablePositionIndependentExecutable {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD3001, "EnablePositionIndependentExecutable")
            .with_category(RuleCategory::Security)
            .with_tags(&[
                "critical",
                "memory-safety",
                "android-cdd",
                "rhel-annocheck",
                "fips",
                "openssf",
            ])
            .with_short_description("Enable Position Independent Executable (PIE) for ASLR.")
            .with_full_description(
                "A Position Independent Executable (PIE) relocates all of its sections at load \
                 time, including the code section, if ASLR is enabled in the Linux kernel \
                 (instead of just the stack/heap). This makes ROP-style attacks more difficult. \
                 This can be enabled by passing '-f pie' to clang/gcc.",
            )
            .with_fix_hint("Compile with -fpie and link with -pie")
            .with_default_level(FailureLevel::Error)
            .with_message("Pass_Executable", "PIE enabled on executable '{0}'.")
            .with_message(
                "Pass_Library",
                "'{0}' is a shared object library rather than an executable, and is \
                 automatically position independent.",
            )
            .with_message(
                "Error",
                "PIE disabled on executable '{0}'. This means the code section will always be \
                 loaded to the same address, even if ASLR is enabled in the Linux kernel. To \
                 address this, ensure you are compiling with '-fpie' when using clang/gcc.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for EnablePositionIndependentExecutable {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnablePositionIndependentExecutable {
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

        // Get ELF-specific data
        let elf = match binary.as_ref().as_any().downcast_ref::<ElfBinary>() {
            Some(elf) => elf,
            None => {
                return (
                    AnalysisApplicability::NotApplicableToSpecifiedTarget,
                    Some("Could not access ELF data".to_string()),
                );
            }
        };

        use aldur_parsers::elf::ElfType;

        // Skip core dumps, relocatables, and unknown types
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

        use aldur_parsers::elf::ElfType;

        match elf.elf_type {
            ElfType::Executable => {
                // Traditional executable - not PIE
                self.log_fail(context, FailureLevel::Error, "Error", &[&file_name]);
            }
            ElfType::SharedObject => {
                if elf.is_pie() {
                    // PIE executable
                    self.log_pass(context, "Pass_Executable", &[&file_name]);
                } else {
                    // Regular shared library
                    self.log_pass(context, "Pass_Library", &[&file_name]);
                }
            }
            _ => {
                self.log_not_applicable(
                    context,
                    "NotApplicable_InvalidMetadata",
                    &[&file_name, self.name(), "Unsupported ELF type"],
                );
            }
        }
    }
}
