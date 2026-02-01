//! AD2015: EnableHighEntropyVirtualAddresses
//!
//! Binaries should be marked as high entropy Address Space Layout Randomization
//! (ASLR) compatible.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::PeBinary;

use crate::rule_ids::AD2015;

pub struct EnableHighEntropyVirtualAddresses {
    descriptor: RuleDescriptor,
}

impl EnableHighEntropyVirtualAddresses {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2015, "EnableHighEntropyVirtualAddresses")
            .with_category(RuleCategory::Security)
            .with_tags(&["critical", "memory-safety", "windows-only", "openssf"])
            .with_short_description("Binaries should be marked as high entropy ASLR compatible.")
            .with_full_description(
                "Binaries should be marked as high entropy Address Space Layout Randomization \
                 (ASLR) compatible. High entropy allows ASLR to be more effective in mitigating \
                 memory corruption vulnerabilities. To resolve this issue, don't set \
                 /HIGHENTROPYVA:NO on link.exe command line and allow it to be enabled by default.",
            )
            .with_fix_hint("Link with /HIGHENTROPYVA (default for 64-bit)")
            .with_default_level(FailureLevel::Error)
            .with_message(
                "Pass",
                "'{0}' is high entropy ASLR compatible, reducing an attacker's ability to \
                 exploit code in well-known locations.",
            )
            .with_message(
                "Error_NoHighEntropyVA",
                "'{0}' does not declare itself as high entropy ASLR compatible. High entropy \
                 makes Address Space Layout Randomization more effective in mitigating memory \
                 corruption vulnerabilities. To resolve this issue, don't set /HIGHENTROPYVA:NO \
                 on link.exe command line.",
            )
            .with_message(
                "Error_NoLargeAddressAware",
                "'{0}' does not declare itself as LARGEADDRESSAWARE. Both /HIGHENTROPYVA and \
                 /LARGEADDRESSAWARE are required for high entropy ASLR.",
            )
            .with_message(
                "Error_Neither",
                "'{0}' does not declare itself as high entropy ASLR compatible. Don't set \
                 /HIGHENTROPYVA:NO and /LARGEADDRESSAWARE:NO on link.exe command line.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for EnableHighEntropyVirtualAddresses {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableHighEntropyVirtualAddresses {
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

        // High entropy VA only applies to 64-bit binaries
        if !binary.is_64_bit() {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Not a 64-bit binary".to_string()),
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

        let has_high_entropy = pe.is_high_entropy_va();
        let has_large_address = pe.is_large_address_aware();

        if has_high_entropy && has_large_address {
            self.log_pass(context, "Pass", &[&file_name]);
        } else if !has_high_entropy && has_large_address {
            self.log_fail(
                context,
                FailureLevel::Error,
                "Error_NoHighEntropyVA",
                &[&file_name],
            );
        } else if has_high_entropy && !has_large_address {
            self.log_fail(
                context,
                FailureLevel::Error,
                "Error_NoLargeAddressAware",
                &[&file_name],
            );
        } else {
            self.log_fail(context, FailureLevel::Error, "Error_Neither", &[&file_name]);
        }
    }
}
