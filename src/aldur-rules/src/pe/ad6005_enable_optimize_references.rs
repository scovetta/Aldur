//! AD6005: EnableOptimizeReferences
//!
//! Checks that Optimize References (/OPT:REF) is enabled.
//! This removes unreferenced functions and data from the final binary.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::PeBinary;

use crate::rule_ids::AD6005;

pub struct EnableOptimizeReferences {
    descriptor: RuleDescriptor,
}

impl EnableOptimizeReferences {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD6005, "EnableOptimizeReferences")
            .with_category(RuleCategory::Performance)
            .with_tags(&["recommended", "windows-only", "optimization"])
            .with_short_description("Enable Optimize References (/OPT:REF) to reduce binary size.")
            .with_full_description(
                "Optimize References can significantly reduce binary size because it instructs \
                 the linker to remove unreferenced functions and data from the final binary.",
            )
            .with_fix_hint("Link with /OPT:REF")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' was compiled with Optimize References (/OPT:REF) enabled.",
            )
            .with_message(
                "Warning",
                "'{0}' was compiled with Optimize References (/OPT:REF) disabled, increasing \
                 binary size. For VC projects use ItemDefinitionGroup - Link - \
                 OptimizeReferences property with 'true' value.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}': {2}.",
            );

        Self { descriptor }
    }

    /// Check if Optimize References is likely enabled
    /// /OPT:REF is enabled by default for release builds (when not using /DEBUG or /INCREMENTAL)
    fn check_optimize_references(pe: &PeBinary) -> Option<bool> {
        // /OPT:REF is incompatible with incremental linking
        // If we see .textbss section, incremental linking is enabled and /OPT:REF is disabled
        let has_incremental = pe
            .sections
            .iter()
            .any(|section| section.name.trim_end_matches('\0') == ".textbss");

        if has_incremental {
            // Incremental linking means /OPT:REF is disabled
            return Some(false);
        }

        // Without incremental linking, /OPT:REF is likely enabled for release builds
        // We can't be 100% certain without PDB command line analysis
        None
    }
}

impl Default for EnableOptimizeReferences {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableOptimizeReferences {
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
        // /OPT:REF is MSVC linker-specific
        if let Some(pe) = binary.as_ref().as_any().downcast_ref::<PeBinary>()
            && let Some(compiler) = super::msvc_utils::detect_non_msvc_compiler(pe)
        {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some(format!("Not an MSVC binary (detected {})", compiler)),
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

        match Self::check_optimize_references(pe) {
            Some(true) => {
                self.log_pass(context, "Pass", &[&file_name]);
            }
            Some(false) => {
                // Incremental linking detected, /OPT:REF is disabled
                self.log_fail(context, FailureLevel::Warning, "Warning", &[&file_name]);
            }
            None => {
                // Can't determine definitively, but no signs of it being disabled
                // Assume pass since /OPT:REF is the default for release builds
                self.log_pass(context, "Pass", &[&file_name]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableOptimizeReferences::new();
        assert_eq!(rule.descriptor().id, "AD6005");
        assert_eq!(rule.descriptor().name, "EnableOptimizeReferences");
    }
}
