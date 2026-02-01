//! AD5026: EnableArmBTIMachO
//!
//! Checks that ARM64 Mach-O binaries (Apple Silicon) have ARM Branch Target
//! Identification (BTI) enabled. BTI provides hardware-based protection against
//! Jump-Oriented Programming (JOP) attacks.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{DwarfInfo, MachOBinary};

use crate::rule_ids::AD5026;

pub struct EnableArmBTIMachO {
    descriptor: RuleDescriptor,
}

impl EnableArmBTIMachO {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD5026, "EnableArmBTIMachO")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "control-flow", "macos-only", "arm-only"])
            .with_short_description(
                "Enable ARM Branch Target Identification (BTI) for Apple Silicon.",
            )
            .with_full_description(
                "ARM Branch Target Identification (BTI) provides hardware-based protection \
                 against Jump-Oriented Programming (JOP) attacks on Apple Silicon (ARM64). \
                 BTI ensures that indirect branches can only land on BTI instructions. \
                 Compile with '-mbranch-protection=standard' or '-mbranch-protection=bti' \
                 to enable BTI. Note: Apple's toolchain may handle this automatically for \
                 arm64e targets.",
            )
            .with_fix_hint("Target arm64e for BTI support on Apple Silicon")
            .with_default_level(FailureLevel::Note)
            .with_message(
                "Pass",
                "'{0}' has ARM BTI enabled or shows signs of branch target identification.",
            )
            .with_message(
                "Pass_DwarfConfirmed",
                "'{0}' has ARM BTI enabled (confirmed via DWARF debug info).",
            )
            .with_message(
                "Note",
                "'{0}' may not have ARM BTI enabled. Consider compiling with \
                 '-mbranch-protection=standard' for hardware-based JOP protection.",
            )
            .with_message(
                "NotApplicable_NotARM64",
                "'{0}' is not an ARM64 binary. ARM BTI only applies to Apple Silicon targets.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }

    /// Check for BTI indicators
    fn check_bti(macho: &MachOBinary) -> (bool, bool) {
        // Check DWARF for BTI flags
        if let Ok(dwarf_info) = DwarfInfo::parse(macho.data()) {
            if dwarf_info.has_debug_info && !dwarf_info.compilation_units.is_empty() {
                let has_bti = dwarf_info.has_flag("-mbranch-protection=standard")
                    || dwarf_info.has_flag("-mbranch-protection=bti")
                    || dwarf_info.has_flag("branch-protection=standard")
                    || dwarf_info.has_flag("branch-protection=bti");

                if has_bti {
                    return (true, true);
                }
            }
        }

        // Look for BTI-related symbols (heuristic)
        let bti_symbols = &["__aarch64_have_bti", "__bti_"];
        if macho.has_any_symbol(bti_symbols) {
            return (true, false);
        }

        (false, false)
    }
}

impl Default for EnableArmBTIMachO {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableArmBTIMachO {
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

        let (has_bti, is_definitive) = Self::check_bti(macho);

        if has_bti {
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
