//! AD3013: ValidateRunpath
//!
//! Validates that RUNPATH entries are secure and don't contain
//! potentially dangerous paths.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::ElfBinary;

use crate::rule_ids::AD3013;

/// Paths that are considered insecure in RUNPATH
const INSECURE_PATH_PATTERNS: &[&str] = &[
    "/tmp",
    "/var/tmp",
    "/home",
    "/users",
    ".",
    "..",
];

pub struct ValidateRunpath {
    descriptor: RuleDescriptor,
}

impl ValidateRunpath {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD3013, "ValidateRunpath")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "linux-only"])
            .with_short_description("Validate that RUNPATH contains only secure paths.")
            .with_full_description(
                "RUNPATH specifies directories to search for shared libraries at runtime. \
                 If RUNPATH contains insecure paths (writable directories, relative paths, \
                 world-writable locations), an attacker could place malicious libraries there. \
                 Only use absolute paths to trusted, non-writable directories.",
            )
            .with_fix_hint("Use absolute paths to non-writable directories in RUNPATH")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' has no RUNPATH or uses only secure paths.",
            )
            .with_message(
                "Warning_InsecurePath",
                "'{0}' has RUNPATH containing potentially insecure path: '{1}'. \
                 Full RUNPATH: '{2}'.",
            )
            .with_message(
                "Warning_RelativePath",
                "'{0}' has RUNPATH containing relative path: '{1}'. \
                 Use absolute paths only. Full RUNPATH: '{2}'.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }

    fn check_runpath(&self, runpath: &str) -> Option<(bool, String)> {
        for path in runpath.split(':') {
            let path = path.trim();
            if path.is_empty() {
                continue;
            }

            // Check for relative paths (except $ORIGIN which is handled specially)
            if !path.starts_with('/') && !path.starts_with("$ORIGIN") {
                return Some((true, path.to_string())); // is_relative = true
            }

            // Check for known insecure patterns
            for pattern in INSECURE_PATH_PATTERNS {
                if path == *pattern || path.starts_with(&format!("{}/", pattern)) {
                    return Some((false, path.to_string())); // is_relative = false
                }
            }
        }
        None
    }
}

impl Default for ValidateRunpath {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for ValidateRunpath {
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

        if binary.format() != BinaryFormat::ELF {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Not an ELF binary".to_string()),
            );
        }

        let elf = match binary.as_ref().as_any().downcast_ref::<ElfBinary>() {
            Some(elf) => elf,
            None => {
                return (
                    AnalysisApplicability::NotApplicableToSpecifiedTarget,
                    Some("Could not access ELF data".to_string()),
                );
            }
        };

        use aldur_parsers::elf::ElfType;

        match elf.elf_type {
            ElfType::Core | ElfType::None | ElfType::Relocatable => {
                return (
                    AnalysisApplicability::NotApplicableToSpecifiedTarget,
                    Some("ELF is core, none, or relocatable".to_string()),
                );
            }
            _ => {}
        }

        (AnalysisApplicability::ApplicableToSpecifiedTarget, None)
    }

    fn analyze(&self, context: &mut AnalysisContext) {
        let file_name = context.file_name();
        let binary = context.binary().expect("Binary must be loaded").clone();

        let elf = match binary.as_ref().as_any().downcast_ref::<ElfBinary>() {
            Some(elf) => elf,
            None => {
                self.log_not_applicable(
                    context,
                    "NotApplicable_InvalidMetadata",
                    &[&file_name, self.name(), "Could not access ELF data"],
                );
                return;
            }
        };

        if let Some(ref runpath) = elf.runpath {
            if let Some((is_relative, bad_path)) = self.check_runpath(runpath) {
                let message_id = if is_relative {
                    "Warning_RelativePath"
                } else {
                    "Warning_InsecurePath"
                };
                self.log_fail(
                    context,
                    FailureLevel::Warning,
                    message_id,
                    &[&file_name, &bad_path, runpath],
                );
            } else {
                self.log_pass(context, "Pass", &[&file_name]);
            }
        } else {
            self.log_pass(context, "Pass", &[&file_name]);
        }
    }
}
