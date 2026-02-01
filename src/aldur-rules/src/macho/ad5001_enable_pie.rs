//! AD5001: EnablePositionIndependentExecutableMachO
//!
//! A Position Independent Executable (PIE) relocates all of its sections at
//! load time if ASLR is enabled.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::MachOBinary;

use crate::rule_ids::AD5001;

pub struct EnablePositionIndependentExecutableMachO {
    descriptor: RuleDescriptor,
}

impl EnablePositionIndependentExecutableMachO {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD5001, "EnablePositionIndependentExecutableMachO")
            .with_category(RuleCategory::Security)
            .with_tags(&["critical", "memory-safety", "macos-only", "openssf"])
            .with_short_description(
                "Enable Position Independent Executable (PIE) for ASLR.",
            )
            .with_full_description(
                "A Position Independent Executable (PIE) relocates all of its sections at load \
                 time, including the code section, if ASLR is enabled in macOS \
                 (instead of just the stack/heap). This makes ROP-style attacks more difficult. \
                 PIE is enabled by default for executables in modern Xcode/clang.",
            )
            .with_fix_hint("Compile with -fPIE (enabled by default in Xcode)")
            .with_default_level(FailureLevel::Error)
            .with_message(
                "Pass",
                "PIE enabled on executable '{0}'.",
            )
            .with_message(
                "Error",
                "PIE disabled on executable '{0}'. This means the code section will always be \
                 loaded to the same address, even if ASLR is enabled. To address this, ensure \
                 you are compiling with '-fpie' when using clang/gcc.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for EnablePositionIndependentExecutableMachO {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnablePositionIndependentExecutableMachO {
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

        if macho.is_pie() {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(context, FailureLevel::Error, "Error", &[&file_name]);
        }
    }
}
