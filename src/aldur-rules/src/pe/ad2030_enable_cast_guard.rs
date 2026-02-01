//! AD2030: EnableCastGuard
//!
//! Ensures binaries are compiled with CastGuard enabled (/guard:cast).
//! CastGuard is a compiler mitigation that validates type casts at runtime
//! to prevent type confusion vulnerabilities in C++ code.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{PdbFile, PeBinary};

use crate::rule_ids::AD2030;

pub struct EnableCastGuard {
    descriptor: RuleDescriptor,
}

impl EnableCastGuard {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2030, "EnableCastGuard")
            .with_category(RuleCategory::Security)
            .with_tags(&["hardening", "memory-safety", "windows-only"])
            .with_short_description("Enable CastGuard for type confusion protection.")
            .with_full_description(
                "CastGuard (/guard:cast) is a compiler mitigation that validates type casts \
                 at runtime to help prevent type confusion vulnerabilities. When enabled, \
                 the compiler inserts runtime checks for static_cast and dynamic_cast \
                 operations involving polymorphic types. This helps detect exploitation \
                 attempts that rely on corrupting vtable pointers or type metadata. \
                 CastGuard requires /guard:cf and /GL (whole program optimization) to be enabled.",
            )
            .with_fix_hint("Compile with /guard:cf /guard:cast /GL")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' is compiled with CastGuard (/guard:cast) enabled.",
            )
            .with_message(
                "Warning_NoCastGuard",
                "'{0}' is not compiled with CastGuard. For Windows and Office teams building \
                 C++ apps using MSVC, consider enabling CastGuard by passing /guard:cast and \
                 /GL on the compiler command line.",
            )
            .with_message(
                "NotApplicable_NotCpp",
                "'{0}' does not appear to be a C++ binary. CastGuard is only applicable to \
                 C++ binaries with polymorphic types.",
            )
            .with_message(
                "NotApplicable_NoPdb",
                "'{0}' does not have an associated PDB file. CastGuard detection requires \
                 debug information.",
            )
            .with_message(
                "NotApplicable_OldCompiler",
                "'{0}' was compiled with a version of the compiler that does not support \
                 CastGuard. Update to Visual Studio 2019 16.10 or later.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}': {2}.",
            )
            .with_message(
                "NotApplicable_NotMsvc",
                "'{0}' was not built with MSVC. The /guard:cast flag is MSVC-specific and \
                 does not apply to binaries compiled with {1}.",
            );

        Self { descriptor }
    }

    /// Check if compiler version supports CastGuard (VS 2019 16.10+, MSVC 19.29+)
    fn supports_cast_guard(major: u16, minor: u16, _build: u16) -> bool {
        // CastGuard was added in VS 2019 16.10 (MSVC 19.29)
        if major > 19 {
            return true;
        }
        if major == 19 && minor >= 29 {
            return true;
        }
        false
    }

    /// Check if the binary appears to be C++ (has C++ symbols or RTTI)
    fn is_cpp_binary(pdb: &PdbFile) -> bool {
        for compiland in &pdb.compilands {
            // Check if the language is C++
            if compiland.compiler.language.contains("Cpp")
                || compiland.compiler.language.contains("C++")
            {
                return true;
            }
        }
        false
    }
}

impl Default for EnableCastGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableCastGuard {
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
        // The /guard:cast flag is MSVC-specific
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

        // Skip .NET binaries - CastGuard is for native C++ only
        if pe.is_dotnet() {
            self.log_not_applicable(context, "NotApplicable_NotCpp", &[&file_name]);
            return;
        }

        // Try to find and load the PDB for compiler info
        let pdb_path = match pe.pdb_path() {
            Some(p) => p,
            None => {
                // Without PDB, we can still check the load config for EH continuation table
                if pe.has_cast_guard() {
                    self.log_pass(context, "Pass", &[&file_name]);
                } else {
                    self.log_not_applicable(context, "NotApplicable_NoPdb", &[&file_name]);
                }
                return;
            }
        };

        let pdb = match PdbFile::load(&pdb_path) {
            Ok(pdb) => pdb,
            Err(_) => {
                // Without PDB, check binary directly
                if pe.has_cast_guard() {
                    self.log_pass(context, "Pass", &[&file_name]);
                } else {
                    self.log_not_applicable(context, "NotApplicable_NoPdb", &[&file_name]);
                }
                return;
            }
        };

        // Check if this is a C++ binary
        if !Self::is_cpp_binary(&pdb) {
            self.log_not_applicable(context, "NotApplicable_NotCpp", &[&file_name]);
            return;
        }

        // Check if compiler version supports CastGuard
        let mut supports_cast_guard = false;
        for compiland in &pdb.compilands {
            let v = compiland.compiler.backend_version;
            if Self::supports_cast_guard(v.0, v.1, v.2) {
                supports_cast_guard = true;
                break;
            }
        }

        if !supports_cast_guard {
            self.log_not_applicable(context, "NotApplicable_OldCompiler", &[&file_name]);
            return;
        }

        // Check if CastGuard is enabled via load config
        if pe.has_cast_guard() {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(
                context,
                FailureLevel::Warning,
                "Warning_NoCastGuard",
                &[&file_name],
            );
        }
    }
}
