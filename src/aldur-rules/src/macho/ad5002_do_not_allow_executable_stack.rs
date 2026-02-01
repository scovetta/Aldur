//! AD5002: DoNotAllowExecutableStack
//!
//! Checks if a binary has an executable stack; an executable stack allows
//! attackers to redirect code flow into stack memory.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::MachOBinary;

use crate::rule_ids::AD5002;

pub struct DoNotAllowExecutableStack {
    descriptor: RuleDescriptor,
}

impl DoNotAllowExecutableStack {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD5002, "DoNotAllowExecutableStack")
            .with_category(RuleCategory::Security)
            .with_tags(&["critical", "memory-safety", "macos-only", "openssf"])
            .with_short_description(
                "Do not allow executable stack.",
            )
            .with_full_description(
                "This checks if a binary has an executable stack; an executable stack allows \
                 attackers to redirect code flow into stack memory, which is an easy place for \
                 an attacker to store shellcode. Ensure do not enable flag '--allow_stack_execute'.",
            )
            .with_fix_hint("Remove -allow_stack_execute linker flag")
            .with_default_level(FailureLevel::Error)
            .with_message(
                "Pass",
                "Executable stack is not allowed on executable '{0}'.",
            )
            .with_message(
                "Error",
                "Stack on '{0}' is executable, which means that an attacker could use it as a \
                 place to store attack shellcode. Ensure do not compile with flag \
                 '--allow_stack_execute' to mark the stack as non-executable.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for DoNotAllowExecutableStack {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DoNotAllowExecutableStack {
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

        if !macho.allows_stack_execution() {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(context, FailureLevel::Error, "Error", &[&file_name]);
        }
    }
}
