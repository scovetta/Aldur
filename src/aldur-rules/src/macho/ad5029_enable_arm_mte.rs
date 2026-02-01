//! AD5029: EnableArmMTEMachO
//!
//! Checks that AArch64 Mach-O binaries have ARM Memory Tagging Extension (MTE) enabled.
//! MTE provides hardware-assisted detection of memory safety bugs such as
//! use-after-free and buffer overflows.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{DwarfInfo, MachOBinary};

use crate::rule_ids::AD5029;

/// ARM MTE-related symbols to look for
const ARM_MTE_SYMBOLS: &[&str] = &[
    "__arm_mte_create_random_tag",
    "__arm_mte_exclude_tag",
    "__arm_mte_get_tag",
    "__arm_mte_increment_tag",
    "__arm_mte_ptrdiff",
    "__arm_mte_set_tag",
    "__hwasan_init",
    "__hwasan_load1",
    "__hwasan_load2",
    "__hwasan_load4",
    "__hwasan_load8",
    "__hwasan_load16",
    "__hwasan_store1",
    "__hwasan_store2",
    "__hwasan_store4",
    "__hwasan_store8",
    "__hwasan_store16",
    "__hwasan_tag_memory",
    "__hwasan_tag_mismatch",
];

pub struct EnableArmMTEMachO {
    descriptor: RuleDescriptor,
}

impl EnableArmMTEMachO {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD5029, "EnableArmMTEMachO")
            .with_category(RuleCategory::Security)
            .with_tags(&["hardening", "memory-safety", "macos-only", "arm-only"])
            .with_short_description("Enable ARM Memory Tagging Extension (MTE) for hardware-assisted memory safety.")
            .with_full_description(
                "ARM Memory Tagging Extension (MTE) provides hardware-assisted detection of \
                 memory safety bugs such as use-after-free and buffer overflows. MTE tags \
                 memory allocations with random tags and validates them on access. When Apple \
                 Silicon supports MTE, compile with '-fsanitize=hwaddress' or '-march=armv8.5-a+memtag' \
                 to enable. Note: MTE hardware support on Apple Silicon may be limited.",
            )
            .with_fix_hint("Compile with -fsanitize=memtag (limited Apple Silicon support)")
            .with_default_level(FailureLevel::Note)
            .with_message(
                "Pass",
                "'{0}' has ARM MTE or HWASan enabled for memory tagging.",
            )
            .with_message(
                "Pass_DwarfConfirmed",
                "'{0}' has ARM MTE enabled (confirmed via DWARF debug info).",
            )
            .with_message(
                "Note",
                "'{0}' does not have ARM MTE enabled. When supported by hardware, consider \
                 enabling MTE with '-fsanitize=hwaddress' for memory safety.",
            )
            .with_message(
                "NotApplicable_NotARM64",
                "'{0}' is not an ARM64 binary. ARM MTE only applies to AArch64.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }

    /// Check for MTE indicators
    fn check_mte(macho: &MachOBinary) -> (bool, bool) {
        // Check DWARF for MTE flags
        if let Ok(dwarf_info) = DwarfInfo::parse(macho.data()) {
            if dwarf_info.has_debug_info && !dwarf_info.compilation_units.is_empty() {
                let has_mte = dwarf_info.has_flag("-fsanitize=hwaddress")
                    || dwarf_info.has_flag("memtag")
                    || dwarf_info.has_flag("-march=armv8.5-a+memtag");

                if has_mte {
                    return (true, true);
                }
            }
        }

        // Check for MTE-related symbols (heuristic)
        if macho.has_any_symbol(ARM_MTE_SYMBOLS) {
            return (true, false);
        }

        (false, false)
    }
}

impl Default for EnableArmMTEMachO {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableArmMTEMachO {
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

        if binary.format() != BinaryFormat::MachO {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Not a Mach-O binary".to_string()),
            );
        }

        let macho = match binary.as_ref().as_any().downcast_ref::<MachOBinary>() {
            Some(macho) => macho,
            None => {
                return (
                    AnalysisApplicability::NotApplicableToSpecifiedTarget,
                    Some("Could not access Mach-O data".to_string()),
                );
            }
        };

        // Only applicable to ARM64
        if !macho.has_arm64() {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Not an ARM64 binary".to_string()),
            );
        }

        use aldur_parsers::macho::MachOType;

        match macho.file_type() {
            Some(MachOType::Object) | Some(MachOType::Core) | Some(MachOType::Dsym) => {
                return (
                    AnalysisApplicability::NotApplicableToSpecifiedTarget,
                    Some("Mach-O is object file, core dump, or dsym".to_string()),
                );
            }
            _ => {}
        }

        (AnalysisApplicability::ApplicableToSpecifiedTarget, None)
    }

    fn analyze(&self, context: &mut AnalysisContext) {
        let file_name = context.file_name();
        let binary = context.binary().expect("Binary must be loaded").clone();

        let macho = match binary.as_ref().as_any().downcast_ref::<MachOBinary>() {
            Some(macho) => macho,
            None => {
                self.log_not_applicable(
                    context,
                    "NotApplicable_InvalidMetadata",
                    &[&file_name, self.name(), "Could not access Mach-O data"],
                );
                return;
            }
        };

        if !macho.has_arm64() {
            self.log_not_applicable(context, "NotApplicable_NotARM64", &[&file_name]);
            return;
        }

        let (has_mte, is_definitive) = Self::check_mte(macho);

        if has_mte {
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
