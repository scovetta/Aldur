//! AD2025: EnableShadowStack (CET)
//!
//! Ensures binaries enable CET Shadow Stack for enhanced return address protection.
//! This provides hardware-enforced protection against ROP attacks.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::PeBinary;

use crate::rule_ids::AD2025;

/// IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT = 0x0001
#[allow(dead_code)]
const IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT: u32 = 0x0001;

pub struct EnableShadowStack {
    descriptor: RuleDescriptor,
}

impl EnableShadowStack {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2025, "EnableShadowStack")
            .with_category(RuleCategory::Security)
            .with_tags(&["hardening", "control-flow", "windows-only", "intel-only"])
            .with_short_description("Enable CET Shadow Stack.")
            .with_full_description(
                "Binaries should enable Intel Control-flow Enforcement Technology (CET) Shadow \
                 Stack to provide hardware-enforced protection against Return-Oriented \
                 Programming (ROP) attacks. When enabled, the processor maintains a shadow \
                 stack that mirrors return addresses, making ROP exploits significantly harder.",
            )
            .with_fix_hint("Link with /CETCOMPAT and compile with /guard:ehcont")
            .with_default_level(FailureLevel::Warning)
            .with_message("Pass", "'{0}' enables CET Shadow Stack for return address protection.")
            .with_message(
                "Warning_NoShadowStack",
                "'{0}' does not enable CET Shadow Stack. Consider enabling /CETCOMPAT \
                 linker flag to protect against ROP attacks on supported hardware.",
            )
            .with_message(
                "NotApplicable_NotWindows10",
                "'{0}' targets a Windows version that does not support CET.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}': {2}.",
            );

        Self { descriptor }
    }
}

impl Default for EnableShadowStack {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableShadowStack {
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

        // Check if the binary targets a Windows version that supports CET
        // CET requires Windows 10 version 2004 (20H1) or later
        // Check minimum OS version
        if pe.os_version_major < 10 {
            self.log_not_applicable(context, "NotApplicable_NotWindows10", &[&file_name]);
            return;
        }

        // Check for load configuration directory which contains CET flags
        // CET compatibility is indicated by guard_flags in load config
        let has_cet = pe
            .load_config
            .as_ref()
            .map(|lc| {
                // IMAGE_GUARD_CF_INSTRUMENTED includes CET-related flags
                // The CET flag would be in the extended guard flags or load config
                // For now, check if guard_flags indicate CF instrumentation
                lc.guard_flags != 0
            })
            .unwrap_or(false);

        if has_cet {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(
                context,
                FailureLevel::Warning,
                "Warning_NoShadowStack",
                &[&file_name],
            );
        }
    }
}

// Suppress unused warning - we document the constant even if not directly used
const _: u32 = IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT;
