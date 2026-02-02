//! AD3039: EnableArmMTE
//!
//! Checks that AArch64 binaries have ARM Memory Tagging Extension (MTE) enabled.
//! MTE provides hardware-assisted detection of memory safety bugs such as
//! use-after-free and buffer overflows.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{DwarfInfo, ElfBinary};

use crate::rule_ids::AD3039;

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

/// EM_AARCH64 machine type constant
const EM_AARCH64: u16 = 0xB7;

pub struct EnableArmMTE {
    descriptor: RuleDescriptor,
}

impl EnableArmMTE {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD3039, "EnableArmMTE")
            .with_category(RuleCategory::Security)
            .with_tags(&["hardening", "memory-safety", "linux-only", "arm-only"])
            .with_short_description(
                "Enable ARM Memory Tagging Extension (MTE) for hardware-assisted memory safety.",
            )
            .with_full_description(
                "ARM Memory Tagging Extension (MTE) is a hardware feature in ARMv8.5-A and \
                 later that provides memory tagging to detect spatial and temporal memory \
                 safety bugs at runtime. MTE assigns a 4-bit tag to each 16-byte memory \
                 granule and checks that pointer tags match memory tags on access, catching \
                 use-after-free and buffer overflow bugs with low overhead. Compile with \
                 '-fsanitize=memtag' or '-march=armv8.5-a+memtag' to enable MTE.",
            )
            .with_fix_hint("Compile with -fsanitize=memtag (ARMv8.5+ only)")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' has ARM Memory Tagging Extension (MTE) enabled.",
            )
            .with_message(
                "Warning",
                "'{0}' does not have ARM Memory Tagging Extension (MTE) enabled. Consider \
                 compiling with '-fsanitize=memtag' or '-march=armv8.5-a+memtag' to enable \
                 hardware-assisted memory safety on supported ARM processors.",
            )
            .with_message(
                "NotApplicable_NotAArch64",
                "'{0}' is not an AArch64 binary. ARM MTE only applies to AArch64.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }

    /// Check if the binary has ARM MTE enabled by looking at DWARF info
    fn has_mte_in_dwarf(elf: &ElfBinary) -> bool {
        // Check DWARF producer strings for MTE-related flags
        if let Ok(dwarf_info) = DwarfInfo::parse(elf.data())
            && dwarf_info.has_debug_info
            && !dwarf_info.compilation_units.is_empty()
        {
            // Check for -fsanitize=memtag or -fsanitize=hwaddress flags
            for cu in &dwarf_info.compilation_units {
                // Check parsed flags for sanitizer options
                for flag in &cu.parsed_info.flags {
                    if flag.contains("memtag") || flag.contains("hwaddress") {
                        return true;
                    }
                }
                // Check producer string for +memtag (from -march=armv8.5-a+memtag)
                if cu.compiler_info.producer.contains("+memtag") {
                    return true;
                }
            }
        }
        false
    }
}

impl Default for EnableArmMTE {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableArmMTE {
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

        // Check if this is an AArch64 binary
        if elf.machine != EM_AARCH64 {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Not an AArch64 binary".to_string()),
            );
        }

        use aldur_parsers::elf::ElfType;

        // Skip core dumps and relocatables
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

        // Check if this is an AArch64 binary
        if elf.machine != EM_AARCH64 {
            self.log_not_applicable(context, "NotApplicable_NotAArch64", &[&file_name]);
            return;
        }

        // Check for MTE via symbols or DWARF info
        let has_mte_symbols = elf.has_any_symbol(ARM_MTE_SYMBOLS);
        let has_mte_dwarf = Self::has_mte_in_dwarf(elf);

        if has_mte_symbols || has_mte_dwarf {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(context, FailureLevel::Warning, "Warning", &[&file_name]);
        }
    }
}
