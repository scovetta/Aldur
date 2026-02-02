//! AD2006: BuildWithSecureTools
//!
//! Ensures binaries are built with a secure/up-to-date compiler toolchain.
//! Older compilers may have bugs or lack security features.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{PdbFile, PeBinary};

use crate::rule_ids::AD2006;

/// Minimum secure MSVC versions by major version
/// These represent versions that have important security fixes
const MIN_MSVC_VERSIONS: &[(u16, u16, u16, u16)] = &[
    // VS 2022 (17.x) - major 19.3x
    (19, 30, 0, 0),
    // VS 2019 (16.x) - major 19.2x
    (19, 20, 0, 0),
    // VS 2017 (15.x) - major 19.1x
    (19, 10, 0, 0),
];

pub struct BuildWithSecureTools {
    descriptor: RuleDescriptor,
}

impl BuildWithSecureTools {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2006, "BuildWithSecureTools")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "windows-only"])
            .with_short_description("Build with secure and up-to-date compiler tools.")
            .with_full_description(
                "Application code should be compiled with the latest tool sets possible to \
                 take advantage of the most current compile-time security features. Among \
                 other things, these features provide address space layout randomization, \
                 help prevent arbitrary code execution, and enable code generation that can \
                 help prevent speculative execution side-channel attacks.",
            )
            .with_fix_hint("Update to latest Visual Studio and Windows SDK")
            .with_default_level(FailureLevel::Error)
            .with_message(
                "Pass",
                "'{0}' was built with a secure compiler version ({1}).",
            )
            .with_message(
                "Error_OutdatedCompiler",
                "'{0}' was built with an outdated compiler version ({1}). Update to a more \
                 recent compiler to enable additional security mitigations.",
            )
            .with_message(
                "Error_UnknownCompiler",
                "'{0}' was built with an unrecognized compiler. Unable to verify security.",
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
                "'{0}' was not built with MSVC. This rule checks MSVC compiler versions \
                 and does not apply to binaries compiled with {1}.",
            );

        Self { descriptor }
    }

    fn check_msvc_version(major: u16, minor: u16, build: u16, qfe: u16) -> bool {
        // Check if version meets any minimum requirement
        for &(min_major, min_minor, min_build, min_qfe) in MIN_MSVC_VERSIONS {
            if major > min_major {
                return true;
            }
            if major == min_major {
                if minor > min_minor {
                    return true;
                }
                if minor == min_minor {
                    if build > min_build {
                        return true;
                    }
                    if build == min_build && qfe >= min_qfe {
                        return true;
                    }
                }
            }
        }
        false
    }
}

impl Default for BuildWithSecureTools {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for BuildWithSecureTools {
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
        // This rule checks MSVC-specific compiler versions
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

        // Check compiler versions for all compilands
        let mut all_secure = true;
        let mut version_string = String::new();

        for compiland in &pdb.compilands {
            let v = compiland.compiler.backend_version;
            if version_string.is_empty() {
                version_string = format!("{}.{}.{}.{}", v.0, v.1, v.2, v.3);
            }

            if !Self::check_msvc_version(v.0, v.1, v.2, v.3) {
                all_secure = false;
                break;
            }
        }

        if pdb.compilands.is_empty() {
            self.log_fail(
                context,
                FailureLevel::Error,
                "Error_UnknownCompiler",
                &[&file_name],
            );
        } else if all_secure {
            self.log_pass(context, "Pass", &[&file_name, &version_string]);
        } else {
            self.log_fail(
                context,
                FailureLevel::Error,
                "Error_OutdatedCompiler",
                &[&file_name, &version_string],
            );
        }
    }
}
