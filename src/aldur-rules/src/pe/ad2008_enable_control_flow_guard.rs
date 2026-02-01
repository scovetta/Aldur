//! AD2008: EnableControlFlowGuard
//!
//! Binaries should enable the compiler control flow guard feature (CFG)
//! at build time to prevent attackers from redirecting execution to
//! unexpected, unsafe locations.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::PeBinary;

use crate::rule_ids::AD2008;

pub struct EnableControlFlowGuard {
    descriptor: RuleDescriptor,
}

impl EnableControlFlowGuard {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2008, "EnableControlFlowGuard")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "control-flow", "windows-only"])
            .with_short_description(
                "Binaries should enable the compiler control flow guard feature (CFG).",
            )
            .with_full_description(
                "Binaries should enable the compiler control flow guard feature (CFG) at build \
                 time to prevent attackers from redirecting execution to unexpected, unsafe \
                 locations. CFG analyzes and discovers all indirect-call instructions at \
                 compilation and link time. It also injects a check that precedes every indirect \
                 call in code that ensures the target is an expected, safe location. If that \
                 check fails at runtime, the operating system will close the program.",
            )
            .with_fix_hint("Compile with /guard:cf and link with /GUARD:CF")
            .with_default_level(FailureLevel::Error)
            .with_message(
                "Pass",
                "'{0}' enables the control flow guard mitigation. As a result, the operating \
                 system will force an application to close if an attacker is able to redirect \
                 execution in the component to an unexpected location.",
            )
            .with_message(
                "Error",
                "'{0}' does not enable the control flow guard (CFG) mitigation. To resolve this \
                 issue, pass /guard:cf on both the compiler and linker command lines. Binaries \
                 also require the /DYNAMICBASE linker option in order to enable CFG.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }

    fn is_applicable(&self, pe: &PeBinary) -> (bool, Option<String>) {
        // CFG requires 64-bit or kernel mode on 64-bit platforms
        // For simplicity, we'll check for minimum linker version (14.0)
        let (major, minor) = pe.linker_version();
        if major < 14 {
            return (
                false,
                Some(format!(
                    "Image was compiled with an outdated toolset (linker version {}.{})",
                    major, minor
                )),
            );
        }

        (true, None)
    }
}

impl Default for EnableControlFlowGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableControlFlowGuard {
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

        if binary.format() != BinaryFormat::PE {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Not a PE binary".to_string()),
            );
        }

        // Get PE-specific data
        let pe = match binary.as_ref().as_any().downcast_ref::<PeBinary>() {
            Some(pe) => pe,
            None => {
                return (
                    AnalysisApplicability::NotApplicableToSpecifiedTarget,
                    Some("Could not access PE data".to_string()),
                );
            }
        };

        let (applicable, reason) = self.is_applicable(pe);
        if !applicable {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                reason,
            );
        }

        (AnalysisApplicability::ApplicableToSpecifiedTarget, None)
    }

    fn analyze(&self, context: &mut AnalysisContext) {
        let file_name = context.file_name();
        let binary = context.binary().expect("Binary must be loaded").clone();

        let pe = match binary.as_ref().as_any().downcast_ref::<PeBinary>() {
            Some(pe) => pe,
            None => {
                self.log_not_applicable(
                    context,
                    "NotApplicable_InvalidMetadata",
                    &[&file_name, self.name(), "Could not access PE data"],
                );
                return;
            }
        };

        if pe.enables_control_flow_guard() {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(context, FailureLevel::Error, "Error", &[&file_name]);
        }
    }
}
