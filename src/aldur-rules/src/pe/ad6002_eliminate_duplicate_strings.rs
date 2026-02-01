//! AD6002: EliminateDuplicateStrings
//!
//! Checks that the /GF compiler option (string pooling) is enabled.
//! This can significantly reduce binary size for programs with many string resources.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{PeBinary, PdbFile};

use crate::rule_ids::AD6002;

pub struct EliminateDuplicateStrings {
    descriptor: RuleDescriptor,
}

impl EliminateDuplicateStrings {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD6002, "EliminateDuplicateStrings")
            .with_category(RuleCategory::Performance)
            .with_tags(&["recommended", "windows-only", "optimization"])
            .with_short_description("Enable string pooling (/GF) to reduce binary size.")
            .with_full_description(
                "The /GF compiler option, also known as Eliminate Duplicate Strings or \
                 String Pooling, will combine identical strings in a program to a single \
                 readonly copy. This can significantly reduce binary size for programs \
                 with many string resources.",
            )
            .with_fix_hint("Compile with /GF")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' was compiled with Eliminate Duplicate Strings (/GF) enabled.",
            )
            .with_message(
                "Warning",
                "'{0}' was compiled without Eliminate Duplicate Strings (/GF) enabled, \
                 increasing binary size. For VC projects use ItemDefinitionGroup - ClCompile - \
                 StringPooling property with 'true' value. The following modules do not \
                 specify that policy: {1}.",
            )
            .with_message(
                "NotApplicable_PdbNotFound",
                "'{0}' does not have an associated PDB file.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}': {2}.",
            )
            .with_message(
                "NotApplicable_NotMsvc",
                "'{0}' was not built with MSVC. The /GF flag is MSVC-specific and \
                 does not apply to binaries compiled with {1}.",
            );

        Self { descriptor }
    }

    /// Check if string pooling is enabled by examining PDB command lines
    /// /GF enables string pooling
    fn check_string_pooling(pdb: &PdbFile) -> (bool, Vec<String>) {
        let mut non_compliant = Vec::new();
        let mut all_compliant = true;

        for compiland in &pdb.compilands {
            if let Some(ref cmd) = compiland.command_line {
                // /GF enables string pooling, /GF- disables it
                // By default in release builds with /O1 or /O2, /GF is enabled
                let has_gf = cmd.contains("/GF") && !cmd.contains("/GF-");
                let has_optimization = cmd.contains("/O1") || cmd.contains("/O2") || cmd.contains("/Ox");

                // /GF is implied by /O1, /O2, /Ox
                if !has_gf && !has_optimization {
                    all_compliant = false;
                    let module_name = compiland.name.rsplit(['\\', '/']).next()
                        .unwrap_or(&compiland.name).to_string();
                    if !non_compliant.contains(&module_name) {
                        non_compliant.push(module_name);
                    }
                }
            }
        }

        (all_compliant, non_compliant)
    }
}

impl Default for EliminateDuplicateStrings {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EliminateDuplicateStrings {
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
        // The /GF flag is MSVC-specific
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

        // Try to load PDB for command line analysis
        let pdb_path = match pe.pdb_path() {
            Some(path) => path,
            None => {
                self.log_not_applicable(context, "NotApplicable_PdbNotFound", &[&file_name]);
                return;
            }
        };

        let pdb = match PdbFile::load(&pdb_path) {
            Ok(pdb) => pdb,
            Err(_) => {
                self.log_not_applicable(context, "NotApplicable_PdbNotFound", &[&file_name]);
                return;
            }
        };

        let (compliant, non_compliant) = Self::check_string_pooling(&pdb);

        if compliant || non_compliant.is_empty() {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            let modules = non_compliant.join(", ");
            self.log_fail(
                context,
                FailureLevel::Warning,
                "Warning",
                &[&file_name, &modules],
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_descriptor() {
        let rule = EliminateDuplicateStrings::new();
        assert_eq!(rule.descriptor().id, "AD6002");
        assert_eq!(rule.descriptor().name, "EliminateDuplicateStrings");
    }
}
