//! AD2026: EnableMicrosoftCompilerSdlSwitch
//!
//! Binaries should be compiled with the /sdl flag to enable additional
//! security-focused warnings and code generation features.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{PdbFile, PeBinary};

use crate::rule_ids::AD2026;

pub struct EnableMicrosoftCompilerSdlSwitch {
    descriptor: RuleDescriptor,
}

impl EnableMicrosoftCompilerSdlSwitch {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2026, "EnableMicrosoftCompilerSdlSwitch")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "memory-safety", "windows-only"])
            .with_short_description(
                "Binaries should be compiled with the /sdl flag for enhanced security checks.",
            )
            .with_full_description(
                "The /sdl (Enable Additional Security Checks) flag enables a superset of the \
                 security checks provided by /GS and overrides /GS-. When /sdl is specified, \
                 the compiler enables strict pointer-type checks, data integrity checks for \
                 run-time function buffers, and enables additional security-focused warnings \
                 as errors. The /sdl flag was introduced in Visual Studio 2012.",
            )
            .with_fix_hint("Compile with /sdl")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' was compiled with /sdl enabled, providing enhanced security checks.",
            )
            .with_message(
                "Warning",
                "'{0}' was not compiled with /sdl enabled. Use /sdl on the compiler command \
                 line to enable additional security checks. Note: /sdl requires Visual Studio \
                 2012 or later.",
            )
            .with_message(
                "Error_NoPdb",
                "'{0}' does not have an associated PDB file or the PDB could not be loaded. \
                 SDL checks status cannot be verified.",
            )
            .with_message(
                "NotApplicable_OldCompiler",
                "'{0}' was compiled with a compiler older than Visual Studio 2012, which does \
                 not support the /sdl flag.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            )
            .with_message(
                "NotApplicable_NotMsvc",
                "'{0}' was not built with MSVC. The /sdl flag is MSVC-specific and \
                 does not apply to binaries compiled with {1}.",
            );

        Self { descriptor }
    }

    fn is_applicable(&self, pe: &PeBinary) -> (bool, Option<String>) {
        // /sdl requires Visual Studio 2012 or later (linker version 11.0+)
        let (major, _) = pe.linker_version();
        if major < 11 {
            return (
                false,
                Some(format!(
                    "Image was compiled with Visual Studio version older than 2012 (linker version {})",
                    major
                )),
            );
        }

        (true, None)
    }
}

impl Default for EnableMicrosoftCompilerSdlSwitch {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableMicrosoftCompilerSdlSwitch {
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

        // Get PE-specific data to check compiler version
        let pe = match binary.as_ref().as_any().downcast_ref::<PeBinary>() {
            Some(pe) => pe,
            None => {
                return (
                    AnalysisApplicability::NotApplicableToSpecifiedTarget,
                    Some("Could not access PE data".to_string()),
                );
            }
        };

        // Check if this is a non-MSVC binary (Rust, GCC, Clang, etc.)
        // The /sdl flag is MSVC-specific
        if let Some(compiler) = super::msvc_utils::detect_non_msvc_compiler(pe) {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some(format!("Not an MSVC binary (detected {})", compiler)),
            );
        }

        let (applicable, reason) = self.is_applicable(pe);
        if !applicable {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                reason,
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

        // Check if all compilands have /sdl enabled
        let all_sdl_enabled = pdb
            .compilands
            .iter()
            .all(|c| c.compiler.sdl_checks == Some(true));

        // If there are no compilands with SDL info, we can't determine
        let has_sdl_info = pdb
            .compilands
            .iter()
            .any(|c| c.compiler.sdl_checks.is_some());

        if !has_sdl_info {
            // No SDL information available in PDB
            self.log_fail(context, FailureLevel::Warning, "Warning", &[&file_name]);
        } else if all_sdl_enabled {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(context, FailureLevel::Warning, "Warning", &[&file_name]);
        }
    }
}
