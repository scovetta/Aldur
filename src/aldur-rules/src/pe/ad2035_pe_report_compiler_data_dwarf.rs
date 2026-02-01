//! AD2035: PeReportCompilerDataDwarf
//!
//! Reports compiler information from DWARF debug info in PE binaries.
//! This is useful for MinGW/Clang builds that use DWARF instead of PDB.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, Binary, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{DwarfInfo, PeBinary};
use aldur_parsers::dwarf::DwarfLanguage;

use crate::rule_ids::AD2035;

pub struct PeReportCompilerDataDwarf {
    descriptor: RuleDescriptor,
}

impl PeReportCompilerDataDwarf {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2035, "PeReportCompilerDataDwarf")
            .with_category(RuleCategory::Reporting)
            .with_tags(&["windows-only"])
            .with_short_description(
                "Report compiler data from DWARF debug info in PE binaries.",
            )
            .with_full_description(
                "This rule reports compiler information extracted from DWARF debug information \
                 in PE binaries. This is useful for understanding the toolchain used to build \
                 MinGW or Clang-compiled Windows binaries. The report includes compiler type, \
                 version, language, optimization level, and security-related compiler flags.",
            )
            .with_fix_hint("Informational only - no fix required")
            .with_default_level(FailureLevel::Note)
            .with_message(
                "CompilerData",
                "DWARF compiler data for '{0}':\n{1}",
            )
            .with_message(
                "NotApplicable_NoDwarf",
                "'{0}' does not contain DWARF debug information.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}': {2}.",
            );

        Self { descriptor }
    }

    /// Format compiler information from DWARF
    fn format_compiler_info(dwarf: &DwarfInfo) -> String {
        let mut lines = Vec::new();

        // Header
        lines.push("CompilationUnit,Compiler,Version,Language,OptLevel,Flags".to_string());

        for (idx, cu) in dwarf.compilation_units.iter().enumerate() {
            let compiler_type = &cu.parsed_info.compiler_type;
            let version = cu
                .parsed_info
                .version
                .map(|(major, minor, patch)| format!("{}.{}.{}", major, minor, patch))
                .unwrap_or_else(|| "Unknown".to_string());

            let language = Self::format_language(&cu.compiler_info.language);

            let opt_level = cu
                .parsed_info
                .optimization_level
                .as_ref()
                .cloned()
                .unwrap_or_else(|| "Unknown".to_string());

            // Collect relevant security flags
            let mut flags = Vec::new();
            if cu.parsed_info.has_stack_protector {
                flags.push("stack-protector");
            }
            if cu.parsed_info.has_lto {
                flags.push("lto");
            }
            if cu.parsed_info.has_stack_clash_protection {
                flags.push("stack-clash-protection");
            }
            if cu.parsed_info.has_fortify_source {
                flags.push("fortify-source");
            }

            let flags_str = if flags.is_empty() {
                "none".to_string()
            } else {
                flags.join(";")
            };

            // Get compilation unit name if available
            let default_name = format!("CU{}", idx);
            let cu_name = cu
                .compiler_info
                .name
                .as_ref()
                .map(|s| {
                    // Get just the filename
                    s.rsplit(['\\', '/']).next().unwrap_or(s)
                })
                .unwrap_or(&default_name);

            lines.push(format!(
                "{},{},{},{},{},{}",
                cu_name, compiler_type, version, language, opt_level, flags_str
            ));
        }

        lines.join("\n")
    }

    /// Format language for display
    fn format_language(lang: &DwarfLanguage) -> String {
        match lang {
            DwarfLanguage::C => "C".to_string(),
            DwarfLanguage::C89 => "C89".to_string(),
            DwarfLanguage::C99 => "C99".to_string(),
            DwarfLanguage::C11 => "C11".to_string(),
            DwarfLanguage::C17 => "C17".to_string(),
            DwarfLanguage::CPlusPlus => "C++".to_string(),
            DwarfLanguage::CPlusPlus03 => "C++03".to_string(),
            DwarfLanguage::CPlusPlus11 => "C++11".to_string(),
            DwarfLanguage::CPlusPlus14 => "C++14".to_string(),
            DwarfLanguage::CPlusPlus17 => "C++17".to_string(),
            DwarfLanguage::CPlusPlus20 => "C++20".to_string(),
            DwarfLanguage::Rust => "Rust".to_string(),
            DwarfLanguage::Go => "Go".to_string(),
            DwarfLanguage::Swift => "Swift".to_string(),
            DwarfLanguage::D => "D".to_string(),
            DwarfLanguage::Fortran => "Fortran".to_string(),
            DwarfLanguage::Ada => "Ada".to_string(),
            DwarfLanguage::Cobol => "COBOL".to_string(),
            DwarfLanguage::Pascal => "Pascal".to_string(),
            DwarfLanguage::Java => "Java".to_string(),
            DwarfLanguage::Python => "Python".to_string(),
            DwarfLanguage::Assembly => "Assembly".to_string(),
            DwarfLanguage::Unknown(code) => format!("Unknown({})", code),
        }
    }

    /// Generate a summary of compiler information
    fn generate_summary(dwarf: &DwarfInfo) -> String {
        let mut summary = Vec::new();

        // Primary compiler
        let primary_compiler = dwarf.primary_compiler();
        summary.push(format!("Primary Compiler: {}", primary_compiler));

        // Languages used
        let languages: Vec<_> = dwarf
            .compilation_units
            .iter()
            .map(|cu| Self::format_language(&cu.compiler_info.language))
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        summary.push(format!("Languages: {}", languages.join(", ")));

        // Compilation unit count
        summary.push(format!(
            "Compilation Units: {}",
            dwarf.compilation_units.len()
        ));

        // Security features summary
        let has_stack_protector = dwarf.has_stack_protector();
        let has_lto = dwarf.has_lto();
        let has_stack_clash = dwarf.has_stack_clash_protection();

        summary.push(format!(
            "Security Features: stack-protector={}, lto={}, stack-clash-protection={}",
            if has_stack_protector { "yes" } else { "no" },
            if has_lto { "yes" } else { "no" },
            if has_stack_clash { "yes" } else { "no" }
        ));

        // Optimization level
        if let Some(opt_level) = dwarf.min_optimization_level() {
            summary.push(format!("Minimum Optimization Level: O{}", opt_level));
        }

        summary.join("\n")
    }
}

impl Default for PeReportCompilerDataDwarf {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for PeReportCompilerDataDwarf {
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

        let pe = match binary.as_ref().as_any().downcast_ref::<PeBinary>() {
            Some(pe) => pe,
            None => {
                return (
                    AnalysisApplicability::NotApplicableToSpecifiedTarget,
                    Some("Could not access PE data".to_string()),
                );
            }
        };

        // Only applicable to PE binaries with DWARF debug info (MinGW/Clang builds)
        if !pe.has_dwarf_debug_info() {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("PE binary does not have DWARF debug info".to_string()),
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

        // Try to load DWARF info
        let dwarf = match DwarfInfo::load(pe.path()) {
            Ok(d) => d,
            Err(_) => {
                self.log_not_applicable(context, "NotApplicable_NoDwarf", &[&file_name]);
                return;
            }
        };

        if !dwarf.has_debug_info || dwarf.compilation_units.is_empty() {
            self.log_not_applicable(
                context,
                "NotApplicable_InvalidMetadata",
                &[
                    &file_name,
                    self.name(),
                    "No compilation units found in DWARF info",
                ],
            );
            return;
        }

        // Generate both summary and detailed CSV data
        let summary = Self::generate_summary(&dwarf);
        let csv_data = Self::format_compiler_info(&dwarf);

        let report = format!("{}\n\nDetailed Data:\n{}", summary, csv_data);

        // Log the compiler data report
        self.log_pass(context, "CompilerData", &[&file_name, &report]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_descriptor() {
        let rule = PeReportCompilerDataDwarf::new();
        assert_eq!(rule.descriptor().id, "AD2035");
        assert_eq!(rule.descriptor().name, "PeReportCompilerDataDwarf");
        assert_eq!(rule.descriptor().category, RuleCategory::Reporting);
    }

    #[test]
    fn test_format_language() {
        assert_eq!(
            PeReportCompilerDataDwarf::format_language(&DwarfLanguage::C),
            "C"
        );
        assert_eq!(
            PeReportCompilerDataDwarf::format_language(&DwarfLanguage::CPlusPlus17),
            "C++17"
        );
        assert_eq!(
            PeReportCompilerDataDwarf::format_language(&DwarfLanguage::Rust),
            "Rust"
        );
    }
}
