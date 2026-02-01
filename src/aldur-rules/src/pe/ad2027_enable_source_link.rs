//! AD2027: EnableSourceLink
//!
//! Ensures binaries have SourceLink information for debugging.
//! SourceLink enables debuggers to automatically download source code.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{PeBinary, PdbFile};

use crate::rule_ids::AD2027;

pub struct EnableSourceLink {
    descriptor: RuleDescriptor,
}

impl EnableSourceLink {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2027, "EnableSourceLink")
            .with_category(RuleCategory::Maintainability)
            .with_tags(&["recommended", "code-integrity", "windows-only"])
            .with_short_description("Enable SourceLink.")
            .with_full_description(
                "Binaries should include SourceLink information in their PDB files. \
                 SourceLink enables debuggers to automatically download matching source \
                 code from source control, improving the debugging and incident response \
                 experience for both developers and security researchers.",
            )
            .with_fix_hint("Add SourceLink NuGet package to project")
            .with_default_level(FailureLevel::Note)
            .with_message(
                "Pass",
                "'{0}' contains SourceLink information for source debugging.",
            )
            .with_message(
                "Note_NoSourceLink",
                "'{0}' does not contain SourceLink information. Consider enabling SourceLink \
                 to allow automatic source code download during debugging.",
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
}

impl Default for EnableSourceLink {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableSourceLink {
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
        // SourceLink/PDB is MSVC-specific debugging
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

        // Try to find and load the PDB
        let pdb_path = match pe.pdb_path() {
            Some(p) => p,
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

        // Check for SourceLink streams in the PDB
        // SourceLink information is stored in named streams like "srcsrv" or "/sourcelink"
        // The PDB crate exposes this through source file information

        // For now, check if we have source file information as a proxy
        // A full implementation would look for the SourceLink JSON stream
        let has_source_info = !pdb.source_files.is_empty();

        // Check for URLs in source file paths (indicates SourceLink)
        let has_source_link = pdb.source_files.iter().any(|sf| {
            sf.name.starts_with("http://")
                || sf.name.starts_with("https://")
                || sf.name.contains("*")
        });

        if has_source_link {
            self.log_pass(context, "Pass", &[&file_name]);
        } else if has_source_info {
            // Has source info but not SourceLink - note but don't fail hard
            self.log_fail(
                context,
                FailureLevel::Note,
                "Note_NoSourceLink",
                &[&file_name],
            );
        } else {
            self.log_fail(
                context,
                FailureLevel::Note,
                "Note_NoSourceLink",
                &[&file_name],
            );
        }
    }
}
