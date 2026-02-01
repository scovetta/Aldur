//! AD3034: RustEnableControlFlowGuard
//!
//! Verifies Rust binaries have Control Flow Guard enabled for Windows targets.
//! For Rust, this is enabled with -Z control-flow-guard.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::PeBinary;

use crate::rule_ids::AD3034;

pub struct RustEnableControlFlowGuard {
    descriptor: RuleDescriptor,
}

impl RustEnableControlFlowGuard {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD3034, "RustEnableControlFlowGuard")
            .with_category(RuleCategory::Security)
            .with_tags(&["nightly", "windows-only"])
            .with_short_description("Enable Control Flow Guard for Rust binaries.")
            .with_full_description(
                "Rust binaries targeting Windows should be compiled with Control Flow Guard \
                 (CFG) enabled. CFG provides protection against control-flow hijacking attacks \
                 by validating indirect call targets at runtime. For Rust, enable CFG using \
                 the unstable flag '-Z control-flow-guard'. This requires a nightly Rust \
                 compiler and targets Windows.",
            )
            .with_fix_hint("Use RUSTFLAGS='-Z control-flow-guard' (nightly only)")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' is a Rust binary with Control Flow Guard enabled.",
            )
            .with_message(
                "Warning_NoCFG",
                "'{0}' is a Rust binary that does not have Control Flow Guard enabled. \
                 Consider compiling with '-Z control-flow-guard' to enable CFG protection. \
                 Note: This requires a nightly Rust compiler.",
            )
            .with_message(
                "NotApplicable_NotRust",
                "'{0}' does not appear to be a Rust binary.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }

    /// Detect if a PE binary was compiled with Rust
    fn is_rust_binary(pe: &PeBinary) -> bool {
        // Check for Rust-specific sections or symbols
        // Common Rust indicators in PE files:
        // - .rustc section (contains Rust metadata)
        // - panic_unwind symbols
        // - rust_eh_personality

        for section in &pe.sections {
            if section.name.contains("rustc") || section.name.contains(".rust") {
                return true;
            }
        }

        // Heuristic: Check if the binary imports from Rust standard library DLLs
        // or has Rust-specific patterns in the binary
        // For now, we'll be conservative and check for .rustc section only
        false
    }
}

impl Default for RustEnableControlFlowGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for RustEnableControlFlowGuard {
    fn descriptor(&self) -> &RuleDescriptor {
        &self.descriptor
    }

    fn can_analyze(
        &self,
        context: &AnalysisContext,
    ) -> (AnalysisApplicability, Option<String>) {
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

        let pe = match binary.as_ref().as_any().downcast_ref::<PeBinary>() {
            Some(pe) => pe,
            None => {
                return (
                    AnalysisApplicability::NotApplicableToSpecifiedTarget,
                    Some("Could not access PE data".to_string()),
                );
            }
        };

        // Skip .NET binaries
        if pe.is_dotnet() {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("This is a .NET binary".to_string()),
            );
        }

        // Only applicable to Rust binaries
        if !Self::is_rust_binary(pe) {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Not a Rust binary".to_string()),
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

        // Verify it's a Rust binary
        if !Self::is_rust_binary(pe) {
            self.log_not_applicable(context, "NotApplicable_NotRust", &[&file_name]);
            return;
        }

        // Check if CFG is enabled
        if pe.enables_control_flow_guard() {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(
                context,
                FailureLevel::Warning,
                "Warning_NoCFG",
                &[&file_name],
            );
        }
    }
}
