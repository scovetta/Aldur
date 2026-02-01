//! AD6001: DisableIncrementalLinkingInReleaseBuilds
//!
//! Checks that incremental linking is disabled in release builds.
//! Incremental linking increases binary size and can reduce performance.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::PeBinary;

use crate::rule_ids::AD6001;

/// The .textbss section is created when incremental linking is enabled
const TEXTBSS_SECTION: &str = ".textbss";

pub struct DisableIncrementalLinkingInReleaseBuilds {
    descriptor: RuleDescriptor,
}

impl DisableIncrementalLinkingInReleaseBuilds {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD6001, "DisableIncrementalLinkingInReleaseBuilds")
            .with_category(RuleCategory::Performance)
            .with_tags(&["recommended", "windows-only", "optimization"])
            .with_short_description("Disable incremental linking in release builds.")
            .with_full_description(
                "Incremental linking support increases binary size and can reduce runtime \
                 performance. The support for incremental linking adds padding and other \
                 overhead to support the ability to modify a binary without a full link. \
                 The use of incrementally linked binaries may reduce the level of \
                 determinism because previous compilations will have lingering effects \
                 on subsequent compilations. Fully optimized release builds should not \
                 specify incremental linking.",
            )
            .with_fix_hint("Link with /INCREMENTAL:NO")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' was compiled with incremental linking disabled.",
            )
            .with_message(
                "Warning",
                "'{0}' appears to be compiled as release but enables incremental linking, \
                 increasing binary size and further compromising runtime performance by \
                 preventing enabling maximal code optimization.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}': {2}.",
            );

        Self { descriptor }
    }

    fn has_incremental_linking(pe: &PeBinary) -> bool {
        // Check for .textbss section which is created by incremental linking
        pe.sections
            .iter()
            .any(|section| section.name.trim_end_matches('\0') == TEXTBSS_SECTION)
    }
}

impl Default for DisableIncrementalLinkingInReleaseBuilds {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DisableIncrementalLinkingInReleaseBuilds {
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

        // Check if this is a non-MSVC binary (Rust, GCC, Clang, etc.)
        // Incremental linking (.textbss) is MSVC-specific
        if let Some(pe) = binary.as_ref().as_any().downcast_ref::<PeBinary>() {
            if let Some(compiler) = super::msvc_utils::detect_non_msvc_compiler(pe) {
                return (
                    AnalysisApplicability::NotApplicableToSpecifiedTarget,
                    Some(format!("Not an MSVC binary (detected {})", compiler)),
                );
            }
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

        let has_incremental = Self::has_incremental_linking(pe);

        if has_incremental {
            // Incremental linking is enabled - this is a warning for release builds
            self.log_fail(context, FailureLevel::Warning, "Warning", &[&file_name]);
        } else {
            self.log_pass(context, "Pass", &[&file_name]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_descriptor() {
        let rule = DisableIncrementalLinkingInReleaseBuilds::new();
        assert_eq!(rule.descriptor().id, "AD6001");
        assert_eq!(
            rule.descriptor().name,
            "DisableIncrementalLinkingInReleaseBuilds"
        );
    }
}
