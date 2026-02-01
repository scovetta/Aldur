//! AD3051: CheckFortifySourceLevel
//!
//! Checks DWARF debug info for FORTIFY_SOURCE level.
//! Recommends level 3 for GCC 12+/Clang 12+ for maximum protection.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{DwarfInfo, ElfBinary};

use crate::rule_ids::AD3051;

pub struct CheckFortifySourceLevel {
    descriptor: RuleDescriptor,
}

impl CheckFortifySourceLevel {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD3051, "CheckFortifySourceLevel")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "memory-safety", "openssf"])
            .with_short_description("Check FORTIFY_SOURCE level in DWARF debug info.")
            .with_full_description(
                "FORTIFY_SOURCE provides different levels of protection: Level 1 provides \
                 compile-time checks only, Level 2 adds runtime checks for stack buffers, \
                 and Level 3 (GCC 12+/Clang 12+) adds runtime checks for heap allocations \
                 using __builtin_dynamic_object_size(). This rule checks DWARF debug info \
                 for the FORTIFY_SOURCE level and recommends upgrading to level 3 when possible.",
            )
            .with_fix_hint("Upgrade to -D_FORTIFY_SOURCE=3 with GCC 12+ or Clang 12+")
            .with_default_level(FailureLevel::Note)
            .with_message(
                "Pass_Level3",
                "'{0}' is compiled with _FORTIFY_SOURCE=3 (maximum protection).",
            )
            .with_message(
                "Pass_Level2",
                "'{0}' is compiled with _FORTIFY_SOURCE=2. Consider upgrading to level 3 \
                 (requires GCC 12+/Clang 12+) for protection of dynamically-allocated buffers.",
            )
            .with_message(
                "Note_Level1",
                "'{0}' is compiled with _FORTIFY_SOURCE=1 (compile-time checks only). \
                 Consider upgrading to level 2 or 3 for runtime overflow detection.",
            )
            .with_message(
                "Note_NotDetected",
                "'{0}' does not have _FORTIFY_SOURCE level detected in DWARF debug info. \
                 Consider compiling with '-D_FORTIFY_SOURCE=3 -O2' for maximum protection.",
            )
            .with_message(
                "NotApplicable_NoDwarf",
                "'{0}' does not contain DWARF debug information.",
            )
            .with_message(
                "NotApplicable_RustBinary",
                "'{0}' is a Rust binary. FORTIFY_SOURCE is not applicable.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}': {2}.",
            );

        Self { descriptor }
    }

    /// Check DWARF for FORTIFY_SOURCE level
    fn check_fortify_level(dwarf: &DwarfInfo) -> FortifyLevel {
        if !dwarf.has_debug_info {
            return FortifyLevel::Unknown;
        }

        for cu in &dwarf.compilation_units {
            let producer = &cu.compiler_info.producer;

            // Check for FORTIFY_SOURCE=3
            if producer.contains("_FORTIFY_SOURCE=3")
                || producer.contains("-D_FORTIFY_SOURCE=3")
                || producer.contains("FORTIFY_SOURCE=3")
            {
                return FortifyLevel::Level3;
            }

            // Check for FORTIFY_SOURCE=2
            if producer.contains("_FORTIFY_SOURCE=2")
                || producer.contains("-D_FORTIFY_SOURCE=2")
                || producer.contains("FORTIFY_SOURCE=2")
            {
                return FortifyLevel::Level2;
            }

            // Check for FORTIFY_SOURCE=1
            if producer.contains("_FORTIFY_SOURCE=1")
                || producer.contains("-D_FORTIFY_SOURCE=1")
                || producer.contains("FORTIFY_SOURCE=1")
            {
                return FortifyLevel::Level1;
            }

            // Check individual flags
            for flag in &cu.parsed_info.flags {
                if flag.contains("FORTIFY_SOURCE=3") {
                    return FortifyLevel::Level3;
                }
                if flag.contains("FORTIFY_SOURCE=2") {
                    return FortifyLevel::Level2;
                }
                if flag.contains("FORTIFY_SOURCE=1") {
                    return FortifyLevel::Level1;
                }
            }
        }

        FortifyLevel::Unknown
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FortifyLevel {
    Level1,
    Level2,
    Level3,
    Unknown,
}

impl Default for CheckFortifySourceLevel {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for CheckFortifySourceLevel {
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

        use aldur_parsers::elf::ElfType;
        match elf.elf_type {
            ElfType::Core | ElfType::None | ElfType::Relocatable => {
                self.log_not_applicable(
                    context,
                    "NotApplicable_InvalidMetadata",
                    &[
                        &file_name,
                        self.name(),
                        "Not an executable or shared library",
                    ],
                );
                return;
            }
            _ => {}
        }

        // FORTIFY_SOURCE is not applicable to Rust binaries
        if elf.is_rust_binary {
            self.log_not_applicable(context, "NotApplicable_RustBinary", &[&file_name]);
            return;
        }

        // Try to parse DWARF
        let dwarf = match DwarfInfo::parse(elf.data()) {
            Ok(d) if d.has_debug_info => d,
            _ => {
                self.log_not_applicable(context, "NotApplicable_NoDwarf", &[&file_name]);
                return;
            }
        };

        match Self::check_fortify_level(&dwarf) {
            FortifyLevel::Level3 => {
                self.log_pass(context, "Pass_Level3", &[&file_name]);
            }
            FortifyLevel::Level2 => {
                self.log_pass(context, "Pass_Level2", &[&file_name]);
            }
            FortifyLevel::Level1 => {
                self.log_fail(context, FailureLevel::Note, "Note_Level1", &[&file_name]);
            }
            FortifyLevel::Unknown => {
                self.log_fail(
                    context,
                    FailureLevel::Note,
                    "Note_NotDetected",
                    &[&file_name],
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
        let rule = CheckFortifySourceLevel::new();
        assert_eq!(rule.descriptor().id, "AD3051");
        assert_eq!(rule.descriptor().name, "CheckFortifySourceLevel");
        assert_eq!(rule.descriptor().category, RuleCategory::Security);
    }
}
