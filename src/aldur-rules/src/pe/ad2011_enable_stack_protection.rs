//! AD2011: EnableStackProtection
//!
//! Binaries should be built with the /GS flag to enable stack buffer
//! overflow detection and protection.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::pe::guard_flags;
use aldur_parsers::{PdbFile, PeBinary};

use crate::rule_ids::AD2011;

pub struct EnableStackProtection {
    descriptor: RuleDescriptor,
}

impl EnableStackProtection {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2011, "EnableStackProtection")
            .with_category(RuleCategory::Security)
            .with_tags(&["critical", "memory-safety", "windows-only", "openssf"])
            .with_short_description(
                "Binaries should be built with the /GS flag to enable stack buffer overflow detection.",
            )
            .with_full_description(
                "Binaries should be built with the /GS flag to enable stack buffer overflow \
                 detection and protection. The /GS flag provides security checks that detect \
                 stack buffer overruns, a common technique for exploiting buffer overrun \
                 vulnerabilities. The security check adds a randomly-initialized security \
                 cookie to the stack frame.",
            )
            .with_fix_hint("Compile with /GS")
            .with_default_level(FailureLevel::Error)
            .with_message(
                "Pass",
                "'{0}' is compiled with /GS enabled, providing stack buffer overflow protection.",
            )
            .with_message(
                "Error",
                "'{0}' was compiled with stack protection disabled. Use the /GS compiler flag \
                 to enable stack buffer overflow protection.",
            )
            .with_message(
                "Error_NoPdb",
                "'{0}' does not have an associated PDB file. Stack protection status cannot be \
                 fully verified. However, the load configuration suggests /GS may be disabled.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }

    fn check_load_config_gs(&self, pe: &PeBinary) -> Option<bool> {
        // Check the load config for security cookie presence
        if let Some(ref config) = pe.load_config {
            // If the guard flags indicate security cookie is unused, /GS is disabled
            if config.guard_flags & guard_flags::SECURITY_COOKIE_UNUSED != 0 {
                return Some(false);
            }
            // If there's a security cookie pointer, /GS is likely enabled
            if config.security_cookie != 0 {
                return Some(true);
            }
        }
        None
    }
}

impl Default for EnableStackProtection {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableStackProtection {
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
        // The /GS flag is MSVC-specific
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

        // First check load configuration for /GS indicators
        if let Some(gs_enabled) = self.check_load_config_gs(pe) {
            if gs_enabled {
                self.log_pass(context, "Pass", &[&file_name]);
            } else {
                self.log_fail(context, FailureLevel::Error, "Error", &[&file_name]);
            }
            return;
        }

        // Try to load the associated PDB file for more detailed analysis
        let pdb_path = match pe.pdb_path() {
            Some(path) => path,
            None => {
                // No PDB, but we can still check the load config
                // If we get here, load config didn't give us a definitive answer
                // Default to warning that we can't fully verify
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

        // Check if any compilands have security checks disabled
        let disabled_gs = pdb.has_disabled_security_checks();
        if !disabled_gs.is_empty() {
            self.log_fail(context, FailureLevel::Error, "Error", &[&file_name]);
        } else {
            self.log_pass(context, "Pass", &[&file_name]);
        }
    }
}
