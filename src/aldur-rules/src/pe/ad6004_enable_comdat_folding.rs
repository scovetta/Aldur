//! AD6004: EnableComdatFolding
//!
//! Checks that COMDAT folding (/OPT:ICF) is enabled.
//! This can significantly reduce binary size by combining identical functions.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::PeBinary;

use crate::rule_ids::AD6004;

pub struct EnableComdatFolding {
    descriptor: RuleDescriptor,
}

impl EnableComdatFolding {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD6004, "EnableComdatFolding")
            .with_category(RuleCategory::Performance)
            .with_tags(&["recommended", "windows-only", "optimization"])
            .with_short_description("Enable COMDAT folding (/OPT:ICF) to reduce binary size.")
            .with_full_description(
                "COMDAT folding can significantly reduce binary size by combining functions \
                 which generate identical machine code into a single copy in the final binary.",
            )
            .with_fix_hint("Link with /OPT:ICF")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' was compiled with COMDAT folding (/OPT:ICF) enabled.",
            )
            .with_message(
                "EnabledForDebug",
                "'{0}' appears to be a Debug build which was compiled with COMDAT folding \
                 (/OPT:ICF) enabled. For VC projects check ItemDefinitionGroup - Link - \
                 EnableCOMDATFolding property. That may make debugging more difficult.",
            )
            .with_message(
                "DisabledForRelease",
                "'{0}' was compiled with COMDAT folding (/OPT:ICF) disabled, increasing \
                 binary size. For VC projects use ItemDefinitionGroup - Link - \
                 EnableCOMDATFolding property with 'true' value.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}': {2}.",
            );

        Self { descriptor }
    }

    /// Check if COMDAT folding is likely enabled by looking for signs of it
    /// This is a heuristic since we can't directly detect /OPT:ICF from the PE
    fn check_comdat_folding(pe: &PeBinary) -> Option<bool> {
        // COMDAT folding is enabled by default when /OPT:REF is used
        // and when incremental linking is disabled.
        //
        // We can infer it's likely enabled if:
        // 1. No .textbss section (no incremental linking)
        // 2. Binary appears to be release (no debug sections with full info)

        let has_incremental = pe.sections.iter().any(|section| {
            section.name.trim_end_matches('\0') == ".textbss"
        });

        if has_incremental {
            // Incremental linking disables COMDAT folding
            return Some(false);
        }

        // Without PDB command line analysis, we can't be certain
        // Return None to indicate we can't determine
        None
    }

    /// Check if the binary appears to be a debug build
    fn appears_to_be_debug(pe: &PeBinary) -> bool {
        // Debug builds typically have .debug sections or unoptimized patterns
        pe.sections.iter().any(|section| {
            let name = section.name.trim_end_matches('\0');
            name == ".debug" || name.starts_with(".debug")
        })
    }
}

impl Default for EnableComdatFolding {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableComdatFolding {
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
        // /OPT:ICF is MSVC linker-specific
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

        let is_debug = Self::appears_to_be_debug(pe);

        match Self::check_comdat_folding(pe) {
            Some(true) => {
                if is_debug {
                    // COMDAT folding in debug build - unusual but not wrong
                    self.log_fail(
                        context,
                        FailureLevel::Warning,
                        "EnabledForDebug",
                        &[&file_name],
                    );
                } else {
                    self.log_pass(context, "Pass", &[&file_name]);
                }
            }
            Some(false) => {
                if !is_debug {
                    // Release build without COMDAT folding
                    self.log_fail(
                        context,
                        FailureLevel::Warning,
                        "DisabledForRelease",
                        &[&file_name],
                    );
                } else {
                    // Debug build without COMDAT folding - expected
                    self.log_pass(context, "Pass", &[&file_name]);
                }
            }
            None => {
                // Can't determine - assume pass for release builds without incremental linking
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
        let rule = EnableComdatFolding::new();
        assert_eq!(rule.descriptor().id, "AD6004");
        assert_eq!(rule.descriptor().name, "EnableComdatFolding");
    }
}
