//! AD2024: EnableSpectreMitigations
//!
//! Ensures binaries are compiled with Spectre mitigations enabled.
//! The /Qspectre flag enables compiler mitigations for Spectre variant 1 attacks.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{PdbFile, PeBinary};

use crate::rule_ids::AD2024;

pub struct EnableSpectreMitigations {
    descriptor: RuleDescriptor,
}

impl EnableSpectreMitigations {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2024, "EnableSpectreMitigations")
            .with_category(RuleCategory::Security)
            .with_tags(&["hardening", "memory-safety", "windows-only", "intel-only"])
            .with_short_description("Enable Spectre mitigations.")
            .with_full_description(
                "Application code should be compiled with Spectre mitigations enabled. \
                 The /Qspectre compiler switch instructs the compiler to insert instructions \
                 that mitigate certain Spectre variant 1 vulnerabilities. These mitigations \
                 help prevent attackers from using speculative execution side-channel attacks \
                 to leak sensitive data.",
            )
            .with_fix_hint("Compile with /Qspectre")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' is compiled with Spectre mitigations (/Qspectre).",
            )
            .with_message(
                "Warning_NoSpectreMitigation",
                "'{0}' is not compiled with Spectre mitigations. Consider adding /Qspectre \
                 to your compiler flags to help protect against Spectre variant 1 attacks.",
            )
            .with_message(
                "NotApplicable_PdbNotFound",
                "'{0}' does not have an associated PDB file.",
            )
            .with_message(
                "NotApplicable_OldCompiler",
                "'{0}' was compiled with a version of the compiler that does not support \
                 Spectre mitigations. Update to Visual Studio 2017 15.5.5 or later.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}': {2}.",
            )
            .with_message(
                "NotApplicable_NotMsvc",
                "'{0}' was not built with MSVC. The /Qspectre flag is MSVC-specific and \
                 does not apply to binaries compiled with {1}.",
            );

        Self { descriptor }
    }

    /// Check if compiler version supports /Qspectre (VS 2017 15.5.5+)
    fn supports_qspectre(major: u16, minor: u16, build: u16) -> bool {
        // /Qspectre was added in VS 2017 15.5.5 (MSVC 19.12.25830)
        if major > 19 {
            return true;
        }
        if major == 19 {
            if minor > 12 {
                return true;
            }
            if minor == 12 && build >= 25830 {
                return true;
            }
        }
        false
    }
}

impl Default for EnableSpectreMitigations {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableSpectreMitigations {
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
        // The /Qspectre flag is MSVC-specific
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

        // First check if the compiler version supports /Qspectre
        let mut supports_spectre = false;
        let mut has_spectre_flag = false;

        for compiland in &pdb.compilands {
            let v = compiland.compiler.backend_version;
            if Self::supports_qspectre(v.0, v.1, v.2) {
                supports_spectre = true;
            }

            // Check for /Qspectre in command line
            if let Some(ref cmdline) = compiland.command_line
                && cmdline.contains("/Qspectre")
                && !cmdline.contains("/Qspectre-")
            {
                has_spectre_flag = true;
            }
        }

        if pdb.compilands.is_empty() {
            self.log_not_applicable(context, "NotApplicable_PdbNotFound", &[&file_name]);
            return;
        }

        if !supports_spectre {
            self.log_not_applicable(context, "NotApplicable_OldCompiler", &[&file_name]);
            return;
        }

        if has_spectre_flag {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(
                context,
                FailureLevel::Warning,
                "Warning_NoSpectreMitigation",
                &[&file_name],
            );
        }
    }
}
