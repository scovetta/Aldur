//! AD5005: DoNotAllowExecutableHeap
//!
//! Checks that the MH_NO_HEAP_EXECUTION flag is set for Mach-O executables.
//! This prevents code execution from the heap, which is a common exploitation technique.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::MachOBinary;

use crate::rule_ids::AD5005;

pub struct DoNotAllowExecutableHeap {
    descriptor: RuleDescriptor,
}

impl DoNotAllowExecutableHeap {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD5005, "DoNotAllowExecutableHeap")
            .with_category(RuleCategory::Security)
            .with_tags(&["critical", "memory-safety", "macos-only"])
            .with_short_description("Do not allow executable heap memory.")
            .with_full_description(
                "The MH_NO_HEAP_EXECUTION flag prevents code execution from heap memory, \
                 which is a common exploitation technique. Attackers often store shellcode \
                 in the heap and redirect execution there. Ensure the linker flag \
                 '-Wl,-no_heap_execution' or '-Wl,-allow_heap_execute' is NOT used.",
            )
            .with_fix_hint("Remove -allow_heap_execute linker flag")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "Heap execution is disabled on '{0}'.",
            )
            .with_message(
                "Warning",
                "Heap execution is allowed on '{0}'. This means an attacker could store \
                 and execute shellcode in heap memory. Consider linking with \
                 '-Wl,-no_heap_execution' to disable heap execution.",
            )
            .with_message(
                "NotApplicable_NotExecutable",
                "'{0}' is not an executable. MH_NO_HEAP_EXECUTION only applies to executables.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for DoNotAllowExecutableHeap {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DoNotAllowExecutableHeap {
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

        // Only applies to executables
        if !macho.is_executable() {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Not an executable".to_string()),
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

        if !macho.is_executable() {
            self.log_not_applicable(context, "NotApplicable_NotExecutable", &[&file_name]);
            return;
        }

        if macho.disallows_heap_execution() {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(context, FailureLevel::Warning, "Warning", &[&file_name]);
        }
    }
}
