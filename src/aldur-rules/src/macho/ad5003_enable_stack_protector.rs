//! AD5003: EnableStackProtectorMachO
//!
//! Checks that stack protector (stack canary) is enabled for Mach-O binaries.
//! This is typically enabled with -fstack-protector, -fstack-protector-strong,
//! or -fstack-protector-all.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::MachOBinary;

use crate::rule_ids::AD5003;

/// Stack protector symbols to look for
const STACK_CHK_SYMBOLS: &[&str] = &[
    "__stack_chk_fail",
    "__stack_chk_guard",
    "___stack_chk_fail",
    "___stack_chk_guard",
];

pub struct EnableStackProtectorMachO {
    descriptor: RuleDescriptor,
}

impl EnableStackProtectorMachO {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD5003, "EnableStackProtectorMachO")
            .with_category(RuleCategory::Security)
            .with_tags(&["critical", "memory-safety", "macos-only", "openssf"])
            .with_short_description("Enable stack protector (stack canary) for buffer overflow protection.")
            .with_full_description(
                "Stack protector adds a 'canary' value between local variables and the return \
                 address on the stack. If a buffer overflow overwrites the canary, the program \
                 will detect this and abort before the corrupted return address is used. Enable \
                 this protection by compiling with '-fstack-protector-strong' or \
                 '-fstack-protector-all'.",
            )
            .with_fix_hint("Compile with -fstack-protector-strong")
            .with_default_level(FailureLevel::Error)
            .with_message(
                "Pass",
                "Stack protector is enabled on '{0}'.",
            )
            .with_message(
                "Error",
                "Stack protector is not enabled on '{0}'. Compile with '-fstack-protector-strong' \
                 or '-fstack-protector-all' to enable this protection.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for EnableStackProtectorMachO {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableStackProtectorMachO {
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

        let macho = match binary.as_ref().as_any().downcast_ref::<MachOBinary>() {
            Some(macho) => macho,
            None => {
                return (
                    AnalysisApplicability::NotApplicableToSpecifiedTarget,
                    Some("Could not access Mach-O data".to_string()),
                );
            }
        };

        use aldur_parsers::macho::MachOType;

        // Skip object files and core dumps
        match macho.file_type() {
            Some(MachOType::Object) | Some(MachOType::Core) | Some(MachOType::Dsym) => {
                return (
                    AnalysisApplicability::NotApplicableToSpecifiedTarget,
                    Some("Mach-O is object file, core dump, or dsym".to_string()),
                );
            }
            _ => {}
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

        if macho.has_any_symbol(STACK_CHK_SYMBOLS) {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(context, FailureLevel::Error, "Error", &[&file_name]);
        }
    }
}
