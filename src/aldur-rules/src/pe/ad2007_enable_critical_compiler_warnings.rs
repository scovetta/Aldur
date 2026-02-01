//! AD2007: EnableCriticalCompilerWarnings
//!
//! Ensures that critical compiler warnings are enabled.
//! These warnings help catch common security issues at compile time.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{PeBinary, PdbFile};

use crate::rule_ids::AD2007;

/// Critical warning IDs that should be treated as errors
const CRITICAL_WARNINGS: &[&str] = &[
    "4018", // signed/unsigned mismatch
    "4146", // unary minus applied to unsigned type
    "4244", // conversion with possible loss of data
    "4267", // conversion from size_t
    "4302", // truncation
    "4308", // negative integral constant converted to unsigned
    "4509", // nonstandard extension: SEH and destructor
    "4532", // jump out of __finally block
    "4533", // initialization skipped by goto
    "4700", // uninitialized variable used
    "4789", // buffer overrun
    "4995", // deprecated function
    "4996", // deprecated function (POSIX)
];

pub struct EnableCriticalCompilerWarnings {
    descriptor: RuleDescriptor,
}

impl EnableCriticalCompilerWarnings {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2007, "EnableCriticalCompilerWarnings")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "windows-only"])
            .with_short_description("Enable critical compiler warnings.")
            .with_full_description(
                "Certain compiler warnings should be enabled and treated as errors to \
                 detect potential security issues in code. These warnings catch common \
                 programming mistakes that could lead to vulnerabilities.",
            )
            .with_fix_hint("Enable /W4 and /WX for warning-as-error")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' has critical compiler warnings enabled.",
            )
            .with_message(
                "Warning_MissingWarnings",
                "'{0}' is missing critical compiler warnings. Ensure /W4 or specific \
                 warning flags are enabled and critical warnings are treated as errors.",
            )
            .with_message(
                "Warning_DisabledWarning",
                "'{0}' has disabled critical warning {1}. This warning should be enabled.",
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
                "'{0}' was not built with MSVC. This rule checks MSVC-specific warning \
                 flags (/W3, /W4, /wd) and does not apply to binaries compiled with {1}.",
            );

        Self { descriptor }
    }

    fn check_warnings_in_commandline(commandline: &str) -> (bool, Vec<String>) {
        let mut disabled_critical = Vec::new();
        let mut has_high_warning_level = false;

        // Check for warning level /W3 or /W4 or /Wall
        if commandline.contains("/W4")
            || commandline.contains("/Wall")
            || commandline.contains("/W3")
        {
            has_high_warning_level = true;
        }

        // Check for disabled critical warnings /wdNNNN
        for warning in CRITICAL_WARNINGS {
            let disable_pattern = format!("/wd{}", warning);
            if commandline.contains(&disable_pattern) {
                disabled_critical.push(warning.to_string());
            }
        }

        (has_high_warning_level, disabled_critical)
    }
}

impl Default for EnableCriticalCompilerWarnings {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableCriticalCompilerWarnings {
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
        // This rule checks MSVC-specific warning flags
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

        // Check compiler command lines for warning settings
        let mut all_have_warnings = true;
        let mut any_disabled_critical = Vec::new();

        for compiland in &pdb.compilands {
            if let Some(ref cmdline) = compiland.command_line {
                let (has_warnings, disabled) = Self::check_warnings_in_commandline(cmdline);
                if !has_warnings {
                    all_have_warnings = false;
                }
                for d in disabled {
                    if !any_disabled_critical.contains(&d) {
                        any_disabled_critical.push(d);
                    }
                }
            }
        }

        if !any_disabled_critical.is_empty() {
            let warnings_str = any_disabled_critical.join(", ");
            self.log_fail(
                context,
                FailureLevel::Warning,
                "Warning_DisabledWarning",
                &[&file_name, &warnings_str],
            );
        } else if all_have_warnings || pdb.compilands.is_empty() {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(
                context,
                FailureLevel::Warning,
                "Warning_MissingWarnings",
                &[&file_name],
            );
        }
    }
}
