//! AD4001: ReportPECompilerData
//!
//! Reports compiler/language/version data for PE binaries to the console.
//! This rule emits CSV data for every compiler/language/version combination
//! observed in any PDB-linked compiland.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{PeBinary, PdbFile};

use crate::rule_ids::AD4001;

pub struct ReportPECompilerData {
    descriptor: RuleDescriptor,
}

impl ReportPECompilerData {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD4001, "ReportPECompilerData")
            .with_category(RuleCategory::Reporting)
            .with_tags(&["windows-only"])
            .with_short_description("Report PE compiler data for analysis.")
            .with_full_description(
                "This rule emits CSV data to the console for every compiler/language/version \
                 combination that's observed in any PDB-linked compiland. This information \
                 is useful for understanding the toolchain used to build a binary and can \
                 help identify outdated or potentially vulnerable compiler versions.",
            )
            .with_fix_hint("Informational only - no fix required")
            .with_default_level(FailureLevel::Note)
            .with_message(
                "CompilerData",
                "Compiler data for '{0}': {1}",
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

    fn format_compiler_info(pdb: &PdbFile) -> String {
        let mut lines = Vec::new();

        // Header
        lines.push("Module,Compiler,Language,FrontendVersion,BackendVersion,SecurityChecks,SdlChecks".to_string());

        for compiland in &pdb.compilands {
            let compiler = &compiland.compiler;
            let frontend_ver = format!(
                "{}.{}.{}.{}",
                compiler.frontend_version.0,
                compiler.frontend_version.1,
                compiler.frontend_version.2,
                compiler.frontend_version.3
            );
            let backend_ver = format!(
                "{}.{}.{}.{}",
                compiler.backend_version.0,
                compiler.backend_version.1,
                compiler.backend_version.2,
                compiler.backend_version.3
            );

            // Skip entries with no compiler info
            if compiler.backend_version.0 == 0 && compiler.backend_version.1 == 0 {
                continue;
            }

            let module_name = compiland.name.rsplit(['\\', '/']).next().unwrap_or(&compiland.name);
            let security = compiler.security_checks.map(|b| if b { "Yes" } else { "No" }).unwrap_or("Unknown");
            let sdl = compiler.sdl_checks.map(|b| if b { "Yes" } else { "No" }).unwrap_or("Unknown");

            // Use actual compiler name from PDB if available, otherwise infer from version
            let compiler_name = if !compiler.name.is_empty() {
                // Shorten long compiler strings for readability
                Self::normalize_compiler_name(&compiler.name)
            } else {
                // Infer compiler from version patterns
                Self::infer_compiler_name(compiler)
            };

            lines.push(format!(
                "{},{},{},{},{},{},{}",
                module_name,
                compiler_name,
                compiler.language,
                frontend_ver,
                backend_ver,
                security,
                sdl
            ));
        }

        lines.join("\n")
    }

    /// Normalize verbose compiler names to short, readable names
    fn normalize_compiler_name(full_name: &str) -> String {
        let lower = full_name.to_lowercase();

        if lower.contains("microsoft") && lower.contains("c/c++") {
            // Extract version from strings like "Microsoft (R) Optimizing Compiler Version 19.29.30133"
            if let Some(ver_start) = full_name.find("Version ") {
                let version = &full_name[ver_start + 8..];
                let major_minor: String = version.chars().take_while(|c| *c != ' ').collect();
                return format!("MSVC {}", major_minor);
            }
            return "MSVC".to_string();
        }

        if lower.contains("clang") {
            // Extract clang version
            if let Some(ver_pos) = lower.find("clang version ") {
                let after = &full_name[ver_pos + 14..];
                let version: String = after.chars().take_while(|c| !c.is_whitespace()).collect();
                return format!("Clang {}", version);
            }
            if lower.contains("clang-cl") {
                return "Clang-CL".to_string();
            }
            return "Clang".to_string();
        }

        if lower.contains("rustc") {
            return "Rust".to_string();
        }

        if lower.contains("gnu") || lower.contains("gcc") {
            return "GCC".to_string();
        }

        // Return shortened version if too long
        if full_name.len() > 30 {
            full_name.chars().take(27).collect::<String>() + "..."
        } else {
            full_name.to_string()
        }
    }

    /// Infer compiler from version number patterns
    fn infer_compiler_name(compiler: &aldur_parsers::pdb::CompilerInfo) -> String {
        let (major, minor, _, _) = compiler.backend_version;

        // MSVC version patterns:
        // 19.x = VS 2015-2022
        // 18.x = VS 2013
        // 17.x = VS 2012
        // 16.x = VS 2010
        if major >= 14 && major <= 19 {
            return format!("MSVC {}.{}", major, minor);
        }

        // Fallback to MSVC for PE binaries with PDB (most common case)
        "MSVC".to_string()
    }
}

impl Default for ReportPECompilerData {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for ReportPECompilerData {
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

        // Check for PDB path
        let pdb_path = match pe.pdb_path() {
            Some(path) => path,
            None => {
                self.log_not_applicable(context, "NotApplicable_PdbNotFound", &[&file_name]);
                return;
            }
        };

        // Load PDB
        let pdb = match PdbFile::load(&pdb_path) {
            Ok(pdb) => pdb,
            Err(_) => {
                self.log_not_applicable(context, "NotApplicable_PdbNotFound", &[&file_name]);
                return;
            }
        };

        // Generate compiler data report
        let compiler_data = Self::format_compiler_info(&pdb);

        if compiler_data.lines().count() <= 1 {
            // Only header, no actual data
            self.log_not_applicable(
                context,
                "NotApplicable_InvalidMetadata",
                &[&file_name, self.name(), "No compiler information found in PDB"],
            );
            return;
        }

        // Use log_pass with Note level for informational output
        self.log_pass(context, "CompilerData", &[&file_name, &compiler_data]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_descriptor() {
        let rule = ReportPECompilerData::new();
        assert_eq!(rule.descriptor().id, "AD4001");
        assert_eq!(rule.descriptor().name, "ReportPECompilerData");
    }
}
