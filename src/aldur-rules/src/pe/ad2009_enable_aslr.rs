//! AD2009: EnableAddressSpaceLayoutRandomization
//!
//! Binaries should be linked as DYNAMICBASE to be eligible for relocation
//! by Address Space Layout Randomization (ASLR).

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::PeBinary;

use crate::rule_ids::AD2009;

pub struct EnableAddressSpaceLayoutRandomization {
    descriptor: RuleDescriptor,
}

impl EnableAddressSpaceLayoutRandomization {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2009, "EnableAddressSpaceLayoutRandomization")
            .with_category(RuleCategory::Security)
            .with_tags(&["critical", "memory-safety", "windows-only", "openssf"])
            .with_short_description("Binaries should be linked as DYNAMICBASE for ASLR.")
            .with_full_description(
                "Binaries should be linked as DYNAMICBASE to be eligible for relocation by \
                 Address Space Layout Randomization (ASLR). ASLR is an important mitigation \
                 that makes it more difficult for an attacker to exploit memory corruption \
                 vulnerabilities. Configure your tools to build with this feature enabled. \
                 For C and C++ binaries, add /DYNAMICBASE to your linker command line.",
            )
            .with_fix_hint("Link with /DYNAMICBASE")
            .with_default_level(FailureLevel::Error)
            .with_message(
                "Pass",
                "'{0}' is properly compiled to enable Address Space Layout Randomization, \
                 reducing an attacker's ability to exploit code in well-known locations.",
            )
            .with_message(
                "Error_NotDynamicBase",
                "'{0}' is not marked as DYNAMICBASE. This means that the binary is not eligible \
                 for relocation by Address Space Layout Randomization (ASLR). ASLR is an important \
                 mitigation that makes it more difficult for an attacker to exploit memory \
                 corruption vulnerabilities.",
            )
            .with_message(
                "Error_RelocsStripped",
                "'{0}' is marked as DYNAMICBASE but relocation data has been stripped from the \
                 image, preventing address space layout randomization.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for EnableAddressSpaceLayoutRandomization {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableAddressSpaceLayoutRandomization {
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

        if !pe.is_dynamic_base() {
            self.log_fail(
                context,
                FailureLevel::Error,
                "Error_NotDynamicBase",
                &[&file_name],
            );
            return;
        }

        if pe.relocs_stripped() {
            self.log_fail(
                context,
                FailureLevel::Error,
                "Error_RelocsStripped",
                &[&file_name],
            );
            return;
        }

        self.log_pass(context, "Pass", &[&file_name]);
    }
}
