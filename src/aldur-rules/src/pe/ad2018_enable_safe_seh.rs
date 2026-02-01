//! AD2018: EnableSafeSEH
//!
//! Binaries should enable SafeSEH (Structured Exception Handling protection)
//! to prevent SEH-based exploitation attacks on 32-bit binaries.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::PeBinary;

use crate::rule_ids::AD2018;

/// x86 machine type constant
const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;

pub struct EnableSafeSEH {
    descriptor: RuleDescriptor,
}

impl EnableSafeSEH {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2018, "EnableSafeSEH")
            .with_category(RuleCategory::Security)
            .with_tags(&["critical", "control-flow", "windows-only", "intel-only"])
            .with_short_description(
                "32-bit binaries should enable SafeSEH to protect against SEH-based attacks.",
            )
            .with_full_description(
                "Structured Exception Handling (SEH) is a mechanism for handling both hardware \
                 and software exceptions on Windows. SEH-based exploitation has been a common \
                 attack vector. SafeSEH is a linker option (/SAFESEH) that creates a table of \
                 valid exception handlers that is validated by the operating system before an \
                 exception handler is called. This helps prevent attackers from redirecting \
                 execution through corrupted exception handlers.",
            )
            .with_fix_hint("Link with /SAFESEH (x86 only)")
            .with_default_level(FailureLevel::Error)
            .with_message(
                "Pass",
                "'{0}' has SafeSEH enabled or uses /NO_SEH, protecting against SEH-based attacks.",
            )
            .with_message(
                "Error",
                "'{0}' is a 32-bit binary that does not have SafeSEH enabled. Compile with \
                 /SAFESEH to enable Structured Exception Handling protection.",
            )
            .with_message(
                "NotApplicable_64Bit",
                "'{0}' is a 64-bit binary. SafeSEH is only applicable to 32-bit x86 binaries.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for EnableSafeSEH {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableSafeSEH {
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

        // SafeSEH only applies to 32-bit x86 binaries
        if binary.is_64_bit() {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("SafeSEH is only applicable to 32-bit binaries".to_string()),
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

        // Double-check this is a 32-bit x86 binary
        if binary.is_64_bit() || pe.machine != IMAGE_FILE_MACHINE_I386 {
            self.log_not_applicable(context, "NotApplicable_64Bit", &[&file_name]);
            return;
        }

        // Check if the binary has NO_SEH flag set (SEH is disabled entirely)
        if pe.has_no_seh() {
            // If SEH is disabled, SafeSEH doesn't apply but the binary is safe
            self.log_pass(context, "Pass", &[&file_name]);
            return;
        }

        // Check for SafeSEH in the load configuration
        if let Some(ref config) = pe.load_config {
            // If SEH handler table is present and count > 0, SafeSEH is enabled
            if config.seh_handler_table != 0 && config.seh_handler_count > 0 {
                self.log_pass(context, "Pass", &[&file_name]);
                return;
            }

            // Minimum load config size for SafeSEH on 32-bit is 0x48
            // which includes the SEH handler table fields
            if config.size >= 0x48 && config.seh_handler_table == 0 {
                // The fields are present but SafeSEH is not configured
                self.log_fail(context, FailureLevel::Error, "Error", &[&file_name]);
                return;
            }
        }

        // No load config or insufficient size - SafeSEH is not enabled
        self.log_fail(context, FailureLevel::Error, "Error", &[&file_name]);
    }
}
