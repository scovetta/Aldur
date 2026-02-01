//! AD3002: DoNotMarkStackAsExecutable
//!
//! Checks if a binary has an executable stack; an executable stack allows
//! attackers to redirect code flow into stack memory.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::ElfBinary;

use crate::rule_ids::AD3002;

pub struct DoNotMarkStackAsExecutable {
    descriptor: RuleDescriptor,
}

impl DoNotMarkStackAsExecutable {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD3002, "DoNotMarkStackAsExecutable")
            .with_category(RuleCategory::Security)
            .with_tags(&[
                "critical",
                "memory-safety",
                "android-cdd",
                "rhel-annocheck",
                "openssf",
            ])
            .with_short_description("Do not mark the stack as executable.")
            .with_full_description(
                "This checks if a binary has an executable stack; an executable stack allows \
                 attackers to redirect code flow into stack memory, which is an easy place for \
                 an attacker to store shellcode. Ensure you are compiling with '-z noexecstack' \
                 to mark the stack as non-executable.",
            )
            .with_fix_hint("Link with -Wl,-z,noexecstack")
            .with_default_level(FailureLevel::Error)
            .with_message(
                "Pass",
                "GNU_STACK segment marked as non-executable on '{0}'.",
            )
            .with_message(
                "Error_StackExec",
                "Stack on '{0}' is executable, which means that an attacker could use it as \
                 a place to store attack shellcode. Ensure you are compiling with '-z noexecstack' \
                 to mark the stack as non-executable.",
            )
            .with_message(
                "Error_NoStackSeg",
                "GNU_STACK segment on '{0}' is missing, which means the stack will likely be \
                 loaded as executable. Ensure you are using an up to date compiler and passing \
                 '-z noexecstack' to the compiler.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for DoNotMarkStackAsExecutable {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DoNotMarkStackAsExecutable {
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

        if !elf.has_gnu_stack {
            self.log_fail(
                context,
                FailureLevel::Error,
                "Error_NoStackSeg",
                &[&file_name],
            );
        } else if elf.has_executable_stack() {
            self.log_fail(
                context,
                FailureLevel::Error,
                "Error_StackExec",
                &[&file_name],
            );
        } else {
            self.log_pass(context, "Pass", &[&file_name]);
        }
    }
}
