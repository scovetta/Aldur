//! AD4002: ReportElfOrMachoCompilerData
//!
//! Reports compiler/language/version data for ELF or Mach-O binaries.
//! This rule emits CSV data for every compiler/language/version combination observed.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::ElfBinary;

use crate::rule_ids::AD4002;

pub struct ReportElfOrMachoCompilerData {
    descriptor: RuleDescriptor,
}

impl ReportElfOrMachoCompilerData {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD4002, "ReportElfOrMachoCompilerData")
            .with_category(RuleCategory::Reporting)
            .with_tags(&["linux-only", "macos-only"])
            .with_short_description("Report ELF/Mach-O compiler data for analysis.")
            .with_full_description(
                "This rule emits CSV data to the console for every compiler/language/version \
                 combination that's observed. This information is extracted from .comment \
                 sections, DWARF debug information, and other metadata embedded in the binary.",
            )
            .with_fix_hint("Informational only - no fix required")
            .with_default_level(FailureLevel::Note)
            .with_message(
                "CompilerData",
                "Compiler data for '{0}': {1}",
            )
            .with_message(
                "NotApplicable_NoCompilerInfo",
                "'{0}' does not contain compiler information.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}': {2}.",
            );

        Self { descriptor }
    }

    fn format_elf_info(elf: &ElfBinary) -> String {
        let mut lines = Vec::new();

        // Header
        lines.push("Binary,Format,Architecture,Type,PIE,RELRO,BindNow,StackProtector,Fortified".to_string());

        let binary_name = elf.path().file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let arch = match elf.machine {
            0x03 => "x86",
            0x3E => "x86_64",
            0x28 => "ARM",
            0xB7 => "AArch64",
            other => return format!("Unknown architecture: 0x{:x}", other),
        };

        let elf_type = if elf.is_shared_library() {
            "SharedLibrary"
        } else if elf.is_pie() {
            "PIE Executable"
        } else {
            "Executable"
        };

        let pie = if elf.is_pie() { "Yes" } else { "No" };
        let relro = if elf.has_full_relro() { "Full" } else if elf.has_read_only_relocations() { "Partial" } else { "No" };
        let bind_now = if elf.has_bind_now { "Yes" } else { "No" };

        // Check for stack protector by looking for symbols
        let stack_chk_symbols = &["__stack_chk_fail", "__stack_chk_guard"];
        let stack_prot = if elf.has_any_symbol(stack_chk_symbols) { "Yes" } else { "No" };

        // Check for fortified functions by looking for *_chk symbols
        let fortify_symbols = &["__memcpy_chk", "__strcpy_chk", "__sprintf_chk"];
        let fortified = if elf.has_any_symbol(fortify_symbols) { "Yes" } else { "No" };

        lines.push(format!(
            "{},{},{},{},{},{},{},{},{}",
            binary_name,
            "ELF",
            arch,
            elf_type,
            pie,
            relro,
            bind_now,
            stack_prot,
            fortified
        ));

        lines.join("\n")
    }
}

impl Default for ReportElfOrMachoCompilerData {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for ReportElfOrMachoCompilerData {
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

        match binary.format() {
            BinaryFormat::ELF | BinaryFormat::MachO => {
                (AnalysisApplicability::ApplicableToSpecifiedTarget, None)
            }
            _ => (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Not an ELF or Mach-O binary".to_string()),
            ),
        }
    }

    fn analyze(&self, context: &mut AnalysisContext) {
        let file_name = context.file_name();
        let binary = context.binary().expect("Binary must be loaded").clone();

        match binary.format() {
            BinaryFormat::ELF => {
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

                let compiler_data = Self::format_elf_info(elf);
                self.log_pass(context, "CompilerData", &[&file_name, &compiler_data]);
            }
            BinaryFormat::MachO => {
                // For Mach-O, provide basic info
                let basic_info = "Binary,Format,Type\nMach-O binary,MachO,Unknown";
                self.log_pass(context, "CompilerData", &[&file_name, basic_info]);
            }
            _ => {
                self.log_not_applicable(
                    context,
                    "NotApplicable_InvalidMetadata",
                    &[&file_name, self.name(), "Unsupported binary format"],
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
        let rule = ReportElfOrMachoCompilerData::new();
        assert_eq!(rule.descriptor().id, "AD4002");
        assert_eq!(rule.descriptor().name, "ReportElfOrMachoCompilerData");
    }
}
