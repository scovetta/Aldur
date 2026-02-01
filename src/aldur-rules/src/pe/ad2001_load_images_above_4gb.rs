//! AD2001: LoadImagesAboveFourGigabyteAddress
//!
//! 64-bit images should have a preferred base address above the 4GB boundary
//! to prevent triggering an ASLR compatibility mode that decreases security.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::PeBinary;

use crate::rule_ids::AD2001;

const FOUR_GB: u64 = 0x1_0000_0000;

pub struct LoadImagesAboveFourGigabyteAddress {
    descriptor: RuleDescriptor,
}

impl LoadImagesAboveFourGigabyteAddress {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2001, "LoadImagesAboveFourGigabyteAddress")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "memory-safety", "windows-only"])
            .with_short_description(
                "64-bit images should have a preferred base address above the 4GB boundary.",
            )
            .with_full_description(
                "64-bit images should have a preferred base address above the 4GB boundary \
                 to prevent triggering an Address Space Layout Randomization (ASLR) compatibility \
                 mode that decreases security. ASLR compatibility mode reduces the number of \
                 locations to which ASLR may relocate the binary, reducing its effectiveness at \
                 mitigating memory corruption vulnerabilities.",
            )
            .with_fix_hint("Link with /HIGHENTROPYVA and do not use /LARGEADDRESSAWARE:NO")
            .with_default_level(FailureLevel::Error)
            .with_message(
                "Pass",
                "'{0}' is a 64-bit image with a base address that is >= 4 gigabytes, \
                 increasing the effectiveness of Address Space Layout Randomization.",
            )
            .with_message(
                "Error",
                "'{0}' is a 64-bit image with a preferred base address below the 4GB boundary. \
                 Having a preferred base address below this boundary triggers a compatibility mode \
                 in Address Space Layout Randomization (ASLR) on recent versions of Windows that \
                 reduces the number of locations to which ASLR may relocate the binary.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for LoadImagesAboveFourGigabyteAddress {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for LoadImagesAboveFourGigabyteAddress {
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

        if !binary.is_64_bit() {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Image is not a 64-bit binary".to_string()),
            );
        }

        (AnalysisApplicability::ApplicableToSpecifiedTarget, None)
    }

    fn analyze(&self, context: &mut AnalysisContext) {
        let file_name = context.file_name();
        let binary = context.binary().expect("Binary must be loaded").clone();

        // Downcast to PeBinary
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

        if pe.image_base >= FOUR_GB {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(context, FailureLevel::Error, "Error", &[&file_name]);
        }
    }
}
