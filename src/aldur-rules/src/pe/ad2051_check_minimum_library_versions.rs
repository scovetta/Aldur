//! AD2051: CheckMinimumLibraryVersions
//!
//! Check that binaries do not use very old versions of MSXML6.dll or XMLlite.dll.
//! Per SDL requirements, MSXML6.dll must be v6.30 or later, and XMLlite.dll must be v1.3 or later.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::PeBinary;

use crate::rule_ids::AD2051;

/// Known vulnerable library patterns
/// Format: (dll_name_pattern, min_major, min_minor, description)
const VULNERABLE_LIBRARIES: &[(&str, u32, u32, &str)] = &[
    ("msxml6", 6, 30, "MSXML6.dll v6.30 or earlier has known vulnerabilities"),
    ("xmllite", 1, 3, "XMLlite.dll v1.3 or earlier has known vulnerabilities"),
];

pub struct CheckMinimumLibraryVersions {
    descriptor: RuleDescriptor,
}

impl CheckMinimumLibraryVersions {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2051, "CheckMinimumLibraryVersions")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "windows-only"])
            .with_short_description(
                "Do not use very old versions of known vulnerable libraries.",
            )
            .with_full_description(
                "Per SDL requirements, binaries must not use very old versions of \
                 MSXML6.dll (v6.30 or earlier) or XMLlite.dll (v1.3 or earlier). These \
                 older library versions have known security vulnerabilities. Update to \
                 newer versions of these libraries to address this issue.",
            )
            .with_fix_hint("Update MSXML6.dll to >6.30 and XMLlite.dll to >1.3")
            .with_default_level(FailureLevel::Error)
            .with_message(
                "Pass",
                "'{0}' does not import any known vulnerable library versions.",
            )
            .with_message(
                "Warning_PotentialVulnerableLibrary",
                "'{0}' imports '{1}' which may be a vulnerable library version. {2} \
                 Verify that the actual library version loaded at runtime meets minimum \
                 requirements.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            )
            .with_message(
                "NotApplicable_NoImports",
                "'{0}' was not evaluated for check '{1}' as no library imports were found.",
            );

        Self { descriptor }
    }

    /// Check if an imported DLL name matches a vulnerable library pattern
    fn check_vulnerable_import(dll_name: &str) -> Option<(&'static str, &'static str)> {
        let lower = dll_name.to_lowercase();
        for (pattern, _min_major, _min_minor, description) in VULNERABLE_LIBRARIES {
            // Match the base name (without version suffix or .dll extension)
            if lower.starts_with(pattern) && lower.ends_with(".dll") {
                // Note: We can only detect that the library is imported, not the actual
                // version that will be loaded at runtime. The version loaded depends on
                // the system DLL search path and installed versions.
                return Some((pattern, *description));
            }
        }
        None
    }
}

impl Default for CheckMinimumLibraryVersions {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for CheckMinimumLibraryVersions {
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

        let imported_dlls = pe.imported_dlls();
        if imported_dlls.is_empty() {
            self.log_not_applicable(
                context,
                "NotApplicable_NoImports",
                &[&file_name, self.name()],
            );
            return;
        }

        let mut vulnerable_found = Vec::new();

        for dll in &imported_dlls {
            if let Some((lib_name, description)) = Self::check_vulnerable_import(dll) {
                vulnerable_found.push((dll.clone(), lib_name, description));
            }
        }

        if vulnerable_found.is_empty() {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            // Report each potentially vulnerable library
            for (dll, _lib_name, description) in vulnerable_found {
                self.log_fail(
                    context,
                    FailureLevel::Warning,
                    "Warning_PotentialVulnerableLibrary",
                    &[&file_name, &dll, description],
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_descriptor() {
        let rule = CheckMinimumLibraryVersions::new();
        assert_eq!(rule.descriptor().id, AD2051);
        assert_eq!(rule.descriptor().name, "CheckMinimumLibraryVersions");
    }

    #[test]
    fn test_vulnerable_import_detection() {
        // Should match
        assert!(CheckMinimumLibraryVersions::check_vulnerable_import("msxml6.dll").is_some());
        assert!(CheckMinimumLibraryVersions::check_vulnerable_import("MSXML6.DLL").is_some());
        assert!(CheckMinimumLibraryVersions::check_vulnerable_import("xmllite.dll").is_some());
        assert!(CheckMinimumLibraryVersions::check_vulnerable_import("XmlLite.DLL").is_some());

        // Should not match
        assert!(CheckMinimumLibraryVersions::check_vulnerable_import("kernel32.dll").is_none());
        assert!(CheckMinimumLibraryVersions::check_vulnerable_import("user32.dll").is_none());
        assert!(CheckMinimumLibraryVersions::check_vulnerable_import("msxml3.dll").is_none());
    }
}
