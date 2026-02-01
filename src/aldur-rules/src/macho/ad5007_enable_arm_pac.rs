//! AD5007: EnableArmPACMachO
//!
//! Checks that ARM64 Mach-O binaries (Apple Silicon) have ARM Pointer
//! Authentication Code (PAC) enabled. PAC provides hardware-based protection
//! against Return-Oriented Programming (ROP) attacks.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{DwarfInfo, MachOBinary};

use crate::rule_ids::AD5007;

/// Symbols that indicate PAC is in use
const PAC_SYMBOLS: &[&str] = &[
    "__ptrauth",
    "ptrauth_sign",
    "ptrauth_auth",
    "ptrauth_strip",
    "ptrauth_blend",
];

pub struct EnableArmPACMachO {
    descriptor: RuleDescriptor,
}

impl EnableArmPACMachO {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD5007, "EnableArmPACMachO")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "control-flow", "macos-only", "arm-only"])
            .with_short_description(
                "Enable ARM Pointer Authentication Code (PAC) for Apple Silicon.",
            )
            .with_full_description(
                "ARM Pointer Authentication Code (PAC) provides hardware-based protection \
                 against Return-Oriented Programming (ROP) attacks on Apple Silicon (ARM64). \
                 PAC signs return addresses and function pointers with a cryptographic signature \
                 that is verified before use. Modern Xcode enables PAC by default for arm64e \
                 architecture. Consider targeting arm64e for maximum protection.",
            )
            .with_fix_hint("Target arm64e architecture for full PAC support")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' has ARM PAC enabled or shows signs of pointer authentication.",
            )
            .with_message(
                "Warning",
                "'{0}' does not appear to use ARM PAC. Consider targeting arm64e architecture \
                 for hardware-based ROP protection on Apple Silicon.",
            )
            .with_message(
                "NotApplicable_NotARM64",
                "'{0}' does not target ARM64. ARM PAC only applies to Apple Silicon (ARM64).",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }

    fn check_pac_in_dwarf(&self, macho: &MachOBinary) -> bool {
        // Check DWARF info for arm64e or PAC-related compiler flags
        if let Ok(dwarf_info) = DwarfInfo::parse(macho.data()) {
            for cu in &dwarf_info.compilation_units {
                // Check if producer string mentions arm64e (PAC-enabled target)
                let producer = &cu.compiler_info.producer;
                if producer.contains("arm64e") || producer.contains("ptrauth") {
                    return true;
                }
            }
        }
        false
    }
}

impl Default for EnableArmPACMachO {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableArmPACMachO {
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

        // Only applies to ARM64 binaries
        if !macho.has_arm64() {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Not an ARM64 binary".to_string()),
            );
        }

        use aldur_parsers::macho::MachOType;

        // Skip object files and core dumps
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

        // Check for PAC symbols or arm64e target
        if macho.has_any_symbol(PAC_SYMBOLS) || self.check_pac_in_dwarf(macho) {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(context, FailureLevel::Warning, "Warning", &[&file_name]);
        }
    }
}
