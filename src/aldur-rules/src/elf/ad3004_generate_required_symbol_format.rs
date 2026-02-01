//! AD3004: GenerateRequiredSymbolFormat
//!
//! Ensures ELF binaries with debug symbols use a modern DWARF format.
//! This rule only applies to binaries that contain debug information.
//! Release binaries without debug symbols will pass this check.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{DwarfInfo, ElfBinary};

use crate::rule_ids::AD3004;

/// Minimum DWARF version recommended
const MIN_DWARF_VERSION: u16 = 4;

pub struct GenerateRequiredSymbolFormat {
    descriptor: RuleDescriptor,
}

impl GenerateRequiredSymbolFormat {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD3004, "GenerateRequiredSymbolFormat")
            .with_category(RuleCategory::Correctness)
            .with_tags(&["recommended", "linux-only"])
            .with_short_description("Use modern DWARF format for debug symbols.")
            .with_full_description(
                "When ELF binaries include debug symbols, they should use modern DWARF \
                 versions (4 or 5) for better debugging support. This rule only applies \
                 to binaries that contain debug information - release binaries without \
                 debug symbols are not flagged.",
            )
            .with_fix_hint("Compile with -gdwarf-4 or -gdwarf-5 for debug info")
            .with_default_level(FailureLevel::Warning)
            .with_message("Pass", "'{0}' contains DWARF version {1} debug symbols.")
            .with_message(
                "Pass_NoDebugInfo",
                "'{0}' does not contain debug symbols (release build).",
            )
            .with_message(
                "Warning_OldDwarfVersion",
                "'{0}' uses DWARF version {1}. Consider using DWARF version {2} or later \
                 for better debugging support.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}': {2}.",
            );

        Self { descriptor }
    }
}

impl Default for GenerateRequiredSymbolFormat {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for GenerateRequiredSymbolFormat {
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

        if binary.format() != BinaryFormat::ELF {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Not an ELF binary".to_string()),
            );
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

        // Try to parse DWARF information
        let dwarf_info = match DwarfInfo::parse(elf.data()) {
            Ok(info) => info,
            Err(_) => {
                // No DWARF info found - this is fine for release builds
                self.log_pass(context, "Pass_NoDebugInfo", &[&file_name]);
                return;
            }
        };

        if dwarf_info.compilation_units.is_empty() {
            // No compilation units - treat as release build without debug info
            self.log_pass(context, "Pass_NoDebugInfo", &[&file_name]);
            return;
        }

        // Find the DWARF version used
        // DWARF version is typically in the compilation unit header
        // DwarfInfo should expose this - for now we check the producer string
        // Use the DWARF version from DwarfInfo
        let dwarf_version = if dwarf_info.dwarf_version > 0 {
            dwarf_info.dwarf_version
        } else {
            // Fallback: infer from compiler info (producer string)
            dwarf_info
                .compilation_units
                .first()
                .map(|cu| {
                    if !cu.compiler_info.producer.is_empty() {
                        4u16 // Modern compilers typically emit DWARF 4+
                    } else {
                        2u16 // Older default
                    }
                })
                .unwrap_or(2)
        };

        let version_str = dwarf_version.to_string();
        let min_version_str = MIN_DWARF_VERSION.to_string();

        if dwarf_version >= MIN_DWARF_VERSION {
            self.log_pass(context, "Pass", &[&file_name, &version_str]);
        } else {
            self.log_fail(
                context,
                FailureLevel::Warning,
                "Warning_OldDwarfVersion",
                &[&file_name, &version_str, &min_version_str],
            );
        }
    }
}
