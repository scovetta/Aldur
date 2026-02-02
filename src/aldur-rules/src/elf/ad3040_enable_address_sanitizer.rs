//! AD3040: EnableAddressSanitizerELF
//!
//! Checks that debug/test builds use AddressSanitizer (ASAN) for memory error detection.
//! This is an informational check - ASAN is typically used in development, not production.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{DwarfInfo, ElfBinary};

use crate::rule_ids::AD3040;

/// ASAN symbols that indicate AddressSanitizer is enabled
const ASAN_SYMBOLS: &[&str] = &[
    "__asan_init",
    "__asan_report_load",
    "__asan_report_store",
    "__asan_register_globals",
    "__asan_version_mismatch_check",
    "__asan_load1",
    "__asan_load2",
    "__asan_load4",
    "__asan_load8",
    "__asan_store1",
    "__asan_store2",
    "__asan_store4",
    "__asan_store8",
    "__asan_handle_no_return",
];

pub struct EnableAddressSanitizerELF {
    descriptor: RuleDescriptor,
}

impl EnableAddressSanitizerELF {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD3040, "EnableAddressSanitizerELF")
            .with_category(RuleCategory::Security)
            .with_tags(&["debug-only", "memory-safety"])
            .with_short_description(
                "Use AddressSanitizer for memory error detection (debug builds).",
            )
            .with_full_description(
                "AddressSanitizer (ASAN) is a fast memory error detector that catches buffer \
                 overflows, use-after-free, and other memory errors at runtime. It should be \
                 enabled during development and testing with '-fsanitize=address'. Note: ASAN \
                 is typically not used in production due to performance overhead (2x slowdown).",
            )
            .with_fix_hint("Compile with -fsanitize=address (debug builds only)")
            .with_default_level(FailureLevel::Note)
            .with_message("Pass", "'{0}' has AddressSanitizer enabled.")
            .with_message(
                "Pass_DwarfConfirmed",
                "'{0}' has AddressSanitizer enabled (confirmed via DWARF debug info).",
            )
            .with_message(
                "Note",
                "'{0}' does not have AddressSanitizer enabled. Consider using ASAN in debug \
                 builds with '-fsanitize=address' to catch memory errors during development.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }

    /// Check for ASAN indicators
    fn check_asan(elf: &ElfBinary) -> (bool, bool) {
        // Check DWARF for ASAN flags
        if let Ok(dwarf_info) = DwarfInfo::parse(elf.data())
            && dwarf_info.has_debug_info
            && !dwarf_info.compilation_units.is_empty()
        {
            let has_asan = dwarf_info.has_flag("-fsanitize=address")
                || dwarf_info.has_flag("sanitize=address");

            if has_asan {
                return (true, true);
            }
        }

        // Check for ASAN-related symbols (heuristic)
        if elf.has_any_symbol(ASAN_SYMBOLS) {
            return (true, false);
        }

        (false, false)
    }
}

impl Default for EnableAddressSanitizerELF {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableAddressSanitizerELF {
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

        let (has_asan, is_definitive) = Self::check_asan(elf);

        if has_asan {
            if is_definitive {
                self.log_pass(context, "Pass_DwarfConfirmed", &[&file_name]);
            } else {
                self.log_pass(context, "Pass", &[&file_name]);
            }
        } else {
            self.log_fail(context, FailureLevel::Note, "Note", &[&file_name]);
        }
    }
}
