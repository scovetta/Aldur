//! AD3003: EnableStackProtector
//!
//! Checks that stack protector (stack canary) is enabled via compiler flags.
//! This is typically enabled with -fstack-protector, -fstack-protector-strong,
//! or -fstack-protector-all.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::ElfBinary;

use crate::rule_ids::AD3003;

/// Stack protector symbols to look for
const STACK_CHK_SYMBOLS: &[&str] = &[
    "__stack_chk_fail",
    "__stack_chk_guard",
    "__stack_smash_handler",
];

pub struct EnableStackProtector {
    descriptor: RuleDescriptor,
}

impl EnableStackProtector {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD3003, "EnableStackProtector")
            .with_category(RuleCategory::Security)
            .with_tags(&[
                "critical",
                "memory-safety",
                "android-cdd",
                "rhel-annocheck",
                "fips",
                "openssf",
            ])
            .with_short_description(
                "Enable stack protector (stack canary) for buffer overflow protection.",
            )
            .with_full_description(
                "Stack protector adds a 'canary' value between local variables and the return \
                 address on the stack. If a buffer overflow overwrites the canary, the program \
                 will detect this and abort before the corrupted return address is used. Enable \
                 this protection by compiling with '-fstack-protector-strong' or \
                 '-fstack-protector-all'.",
            )
            .with_fix_hint("Compile with -fstack-protector-strong or -fstack-protector-all")
            .with_default_level(FailureLevel::Error)
            .with_message("Pass", "Stack protector is enabled on '{0}'.")
            .with_message(
                "Error",
                "Stack protector is not enabled on '{0}'. Compile with '-fstack-protector-strong' \
                 or '-fstack-protector-all' to enable this protection.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            )
            .with_message(
                "NotApplicable_RustBinary",
                "'{0}' is a Rust binary. Stack protector (__stack_chk_fail) is a C/C++ \
                 mechanism; Rust uses built-in bounds checking for memory safety.",
            );

        Self { descriptor }
    }
}

impl Default for EnableStackProtector {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableStackProtector {
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

        // Skip core dumps and relocatables
        match elf.elf_type {
            ElfType::Core | ElfType::None | ElfType::Relocatable => {
                return (
                    AnalysisApplicability::NotApplicableToSpecifiedTarget,
                    Some("ELF is core, none, or relocatable".to_string()),
                );
            }
            _ => {}
        }

        // Stack protector is a C/C++ mechanism that doesn't apply to pure Rust binaries
        // Rust has built-in bounds checking that provides equivalent protection
        if elf.is_rust_binary {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Rust binary - uses built-in bounds checking instead".to_string()),
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

        if elf.has_any_symbol(STACK_CHK_SYMBOLS) {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(context, FailureLevel::Error, "Error", &[&file_name]);
        }
    }
}
