//! AD2014: DoNotDisableStackProtectionForFunctions
//!
//! Ensures that stack protection is not disabled for individual functions.
//! Using #pragma or __declspec to disable /GS for specific functions weakens security.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{PeBinary, PdbFile};

use crate::rule_ids::AD2014;

pub struct DoNotDisableStackProtectionForFunctions {
    descriptor: RuleDescriptor,
}

impl DoNotDisableStackProtectionForFunctions {
    pub fn new() -> Self {
        let descriptor =
            RuleDescriptor::new(AD2014, "DoNotDisableStackProtectionForFunctions")
                .with_category(RuleCategory::Security)
                .with_tags(&["recommended", "memory-safety", "windows-only"])
                .with_short_description(
                    "Do not disable stack protection for individual functions.",
                )
                .with_full_description(
                    "Application code should not disable stack protection for specific functions \
                 using #pragma strict_gs_check(off), #pragma runtime_checks, or \
                 __declspec(safebuffers). These mechanisms bypass the security provided by /GS.",
                )
            .with_fix_hint("Remove #pragma strict_gs_check(off) and __declspec(safebuffers)")
                .with_default_level(FailureLevel::Warning)
                .with_message(
                    "Pass",
                    "'{0}' does not disable stack protection for any functions.",
                )
                .with_message(
                    "Warning_DisabledForFunctions",
                    "'{0}' may have disabled stack protection for some functions. Check for use \
                 of #pragma strict_gs_check(off), #pragma runtime_checks, or \
                 __declspec(safebuffers) in source code.",
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

impl Default for DoNotDisableStackProtectionForFunctions {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DoNotDisableStackProtectionForFunctions {
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
        // The #pragma strict_gs_check is MSVC-specific
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

        // Check compilands for disabled security checks
        let has_disabled_gs = !pdb.has_disabled_security_checks().is_empty();

        // Also check command lines for /GS- which disables entirely
        let has_gs_disabled_flag = pdb.compilands.iter().any(|c| {
            if let Some(ref cmdline) = c.command_line {
                // /GS- disables stack protection
                cmdline.contains("/GS-")
            } else {
                false
            }
        });

        if has_disabled_gs || has_gs_disabled_flag {
            self.log_fail(
                context,
                FailureLevel::Warning,
                "Warning_DisabledForFunctions",
                &[&file_name],
            );
        } else {
            self.log_pass(context, "Pass", &[&file_name]);
        }
    }
}
