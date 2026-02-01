//! AD2004: EnableSecureSourceCodeHashing
//!
//! Compilers can generate checksums for source files to help verify that
//! a binary was built from the source code it claims. Enable SHA-256
//! for source file checksums in PDB files.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{PdbFile, PeBinary};

use crate::rule_ids::AD2004;

pub struct EnableSecureSourceCodeHashing {
    descriptor: RuleDescriptor,
}

impl EnableSecureSourceCodeHashing {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2004, "EnableSecureSourceCodeHashing")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "code-integrity", "windows-only"])
            .with_short_description(
                "Compilers should hash source files using SHA-256 in PDB files.",
            )
            .with_full_description(
                "Compilers can optionally generate checksums (hashes) of source files when \
                 emitting debug information. These checksums help verify that a binary was \
                 built from the source code it claims. The /ZH:SHA_256 flag instructs the \
                 compiler to use SHA-256 for source file hashing. Insecure algorithms like \
                 MD5 or SHA-1 are considered deprecated for security purposes.",
            )
            .with_fix_hint("Compile with /ZH:SHA_256")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' uses secure SHA-256 hashing for all source file references in its PDB.",
            )
            .with_message(
                "Warning",
                "'{0}' uses an insecure hashing algorithm (MD5 or SHA-1) for one or more \
                 source file references in its PDB. Use /ZH:SHA_256 on the compiler command \
                 line to enable secure source code hashing.",
            )
            .with_message(
                "Error_NoPdb",
                "'{0}' does not have an associated PDB file or the PDB could not be loaded. \
                 Source code hashing cannot be verified.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            )
            .with_message(
                "NotApplicable_NotMsvc",
                "'{0}' was not built with MSVC. The /ZH:SHA_256 flag is MSVC-specific and \
                 does not apply to binaries compiled with {1}.",
            );

        Self { descriptor }
    }
}

impl Default for EnableSecureSourceCodeHashing {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableSecureSourceCodeHashing {
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
        // The /ZH:SHA_256 flag is MSVC-specific
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

        // Try to load the associated PDB file
        let pdb_path = match pe.pdb_path() {
            Some(path) => path,
            None => {
                self.log_fail(context, FailureLevel::Warning, "Error_NoPdb", &[&file_name]);
                return;
            }
        };

        let pdb = match PdbFile::load(&pdb_path) {
            Ok(pdb) => pdb,
            Err(_) => {
                self.log_fail(context, FailureLevel::Warning, "Error_NoPdb", &[&file_name]);
                return;
            }
        };

        // Check if any source files use insecure hashing
        if pdb.has_insecure_source_hashing() {
            self.log_fail(context, FailureLevel::Warning, "Warning", &[&file_name]);
        } else {
            self.log_pass(context, "Pass", &[&file_name]);
        }
    }
}
