//! AD3006: EnableNonExecutableStack
//!
//! Ensure that non-executable stack is enabled.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::ElfBinary;

use crate::rule_ids::AD3006;

pub struct EnableNonExecutableStack {
    descriptor: RuleDescriptor,
}

impl EnableNonExecutableStack {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD3006, "EnableNonExecutableStack")
            .with_category(RuleCategory::Security)
            .with_tags(&[
                "critical",
                "memory-safety",
                "android-cdd",
                "rhel-annocheck",
                "openssf",
            ])
            .with_short_description("Enable non-executable stack.")
            .with_full_description(
                "This check ensures that non-executable stack is enabled. A common type of \
                 exploit is the stack buffer overflow. An application receives, from an attacker, \
                 more data than it is prepared for and stores this information on its stack, \
                 writing beyond the space reserved for it. This can be designed to cause \
                 execution of the data written on the stack. One mechanism to mitigate this \
                 vulnerability is for the system to not allow the execution of instructions \
                 in sections of memory identified as part of the stack. Use the compiler flags \
                 '-z noexecstack' to enable this.",
            )
            .with_fix_hint("Link with -Wl,-z,noexecstack")
            .with_default_level(FailureLevel::Error)
            .with_message(
                "Pass",
                "The non-executable stack flag was present, so '{0}' is protected.",
            )
            .with_message(
                "Error",
                "The non-executable stack is not enabled for this binary, so '{0}' can have a \
                 vulnerability of execution of the data written on the stack. Ensure you are \
                 compiling with the flag '-z noexecstack' to address this.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for EnableNonExecutableStack {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableNonExecutableStack {
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

        // Skip object files - linker flags are not applicable
        let elf = match binary.as_ref().as_any().downcast_ref::<ElfBinary>() {
            Some(elf) => elf,
            None => {
                return (
                    AnalysisApplicability::NotApplicableToSpecifiedTarget,
                    Some("Could not access ELF data".to_string()),
                );
            }
        };

        if elf.is_object_file() {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Object files do not have linker-level protections".to_string()),
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

        if elf.has_non_executable_stack() {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(context, FailureLevel::Error, "Error", &[&file_name]);
        }
    }
}
