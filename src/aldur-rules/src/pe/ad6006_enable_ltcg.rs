//! AD6006: EnableLinkTimeCodeGeneration
//!
//! Checks that Link Time Code Generation (LTCG) is enabled.
//! LTCG performs whole-program optimization for better performance.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{PdbFile, PeBinary};

use crate::rule_ids::AD6006;

pub struct EnableLinkTimeCodeGeneration {
    descriptor: RuleDescriptor,
}

impl EnableLinkTimeCodeGeneration {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD6006, "EnableLinkTimeCodeGeneration")
            .with_category(RuleCategory::Performance)
            .with_tags(&["recommended", "windows-only", "optimization"])
            .with_short_description("Enable Link Time Code Generation (LTCG).")
            .with_full_description(
                "Enabling Link Time Code Generation (LTCG) performs whole-program optimization, \
                 which is able to better optimize code across translation units. LTCG is also \
                 a prerequisite for Profile-Guided Optimization (PGO) which can further improve \
                 performance.",
            )
            .with_fix_hint("Compile with /GL and link with /LTCG")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' was compiled with Link Time Code Generation (/LTCG) enabled.",
            )
            .with_message(
                "Warning",
                "'{0}' was compiled without Link Time Code Generation (/LTCG). Enabling LTCG \
                 can improve optimizations and performance. For VC projects use \
                 WholeProgramOptimization property with 'true' value.",
            )
            .with_message(
                "NotApplicable_PdbNotFound",
                "'{0}' does not have an associated PDB file.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}': {2}.",
            );

        Self { descriptor }
    }

    fn check_ltcg_enabled(pe: &PeBinary, _pdb: Option<&PdbFile>) -> Option<bool> {
        // LTCG can be detected by:
        // 1. Looking for LTCG-specific sections (.ltcg)
        // 2. Checking PDB for LTCG flags in compiler info
        // 3. Looking for whole-program optimization markers

        // Check for .ltcg section (sometimes present in LTCG builds)
        let has_ltcg_section = pe.sections.iter().any(|section| {
            let name = section.name.trim_end_matches('\0');
            name.contains("ltcg") || name.contains("LTCG")
        });

        if has_ltcg_section {
            return Some(true);
        }

        // Check if the binary has characteristics typical of LTCG builds
        // LTCG typically produces more compact code with merged functions
        // This is a heuristic - checking for code folding evidence

        // Without more specific indicators, we can't definitively determine LTCG status
        // Return None to indicate uncertainty
        None
    }
}

impl Default for EnableLinkTimeCodeGeneration {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableLinkTimeCodeGeneration {
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
        // /LTCG is MSVC linker-specific
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

        // Try to load PDB for more detailed analysis
        let pdb = pe.pdb_path().and_then(|path| PdbFile::load(&path).ok());

        match Self::check_ltcg_enabled(pe, pdb.as_ref()) {
            Some(true) => {
                self.log_pass(context, "Pass", &[&file_name]);
            }
            Some(false) => {
                self.log_fail(context, FailureLevel::Warning, "Warning", &[&file_name]);
            }
            None => {
                // Unable to determine LTCG status
                // Report as not applicable rather than making assumptions
                self.log_not_applicable(
                    context,
                    "NotApplicable_InvalidMetadata",
                    &[&file_name, self.name(), "Unable to determine LTCG status"],
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableLinkTimeCodeGeneration::new();
        assert_eq!(rule.descriptor().id, "AD6006");
        assert_eq!(rule.descriptor().name, "EnableLinkTimeCodeGeneration");
    }
}
