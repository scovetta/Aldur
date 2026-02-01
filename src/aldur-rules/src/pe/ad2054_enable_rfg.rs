//! AD2054: EnableReturnFlowGuard
//!
//! Checks that PE binaries have Return Flow Guard (RFG) enabled if available.
//! RFG provides additional protection against return-oriented programming attacks.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::PeBinary;

use crate::rule_ids::AD2054;

pub struct EnableReturnFlowGuard {
    descriptor: RuleDescriptor,
}

impl EnableReturnFlowGuard {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2054, "EnableReturnFlowGuard")
            .with_category(RuleCategory::Security)
            .with_tags(&["hardening", "control-flow", "windows-only"])
            .with_short_description("Binaries should enable Return Flow Guard for return address protection.")
            .with_full_description(
                "Return Flow Guard (RFG) is a security feature that protects against \
                 return-oriented programming (ROP) attacks by validating return addresses \
                 at runtime. RFG maintains a shadow return stack to verify that return \
                 addresses have not been tampered with. This provides defense-in-depth \
                 alongside other mitigations like Control Flow Guard (CFG) and CET Shadow Stack. \
                 Note: RFG was a planned feature that was ultimately superseded by CET Shadow Stack \
                 in modern Windows versions.",
            )
            .with_fix_hint("Informational - RFG is a future/experimental feature")
            .with_default_level(FailureLevel::Note)
            .with_message(
                "Pass",
                "'{0}' has Return Flow Guard enabled.",
            )
            .with_message(
                "Note_NoRFG",
                "'{0}' does not have Return Flow Guard enabled. Consider enabling CET Shadow Stack \
                 (/CETCOMPAT) for similar return address protection on modern systems.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}': {2}.",
            );

        Self { descriptor }
    }
}

impl Default for EnableReturnFlowGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableReturnFlowGuard {
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

        if binary.format() != BinaryFormat::PE {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Not a PE binary".to_string()),
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

        if pe.has_rfg() {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(context, FailureLevel::Note, "Note_NoRFG", &[&file_name]);
        }
    }
}
