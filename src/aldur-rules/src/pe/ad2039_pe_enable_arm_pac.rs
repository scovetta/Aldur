//! AD2039: PeEnableArmPAC
//!
//! Checks for ARM Pointer Authentication Code (PAC) in Windows on ARM PE binaries.
//! Verifies that -mbranch-protection=standard or -mbranch-protection=pac-ret is used.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, Binary, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{DwarfInfo, PeBinary};

use crate::rule_ids::AD2039;

pub struct PeEnableArmPAC {
    descriptor: RuleDescriptor,
}

impl PeEnableArmPAC {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2039, "PeEnableArmPAC")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "control-flow", "windows-only", "arm-only"])
            .with_short_description(
                "Enable ARM Pointer Authentication Code (PAC) for Windows on ARM PE binaries.",
            )
            .with_full_description(
                "Windows on ARM PE binaries should be compiled with ARM Pointer Authentication \
                 Code (PAC) enabled. PAC is a security feature that uses cryptographic signatures \
                 to protect return addresses and other code pointers, helping to prevent \
                 Return-Oriented Programming (ROP) attacks. Enable PAC by compiling with \
                 '-mbranch-protection=standard' or '-mbranch-protection=pac-ret'. This rule \
                 checks for the presence of these flags in DWARF debug information.",
            )
            .with_fix_hint("Compile with -mbranch-protection=standard (ARM64 only)")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' was compiled with ARM PAC enabled.",
            )
            .with_message(
                "Warning",
                "'{0}' was not compiled with ARM PAC. Consider using \
                 '-mbranch-protection=standard' or '-mbranch-protection=pac-ret' for improved \
                 security against ROP attacks on ARM64 platforms.",
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

    /// Check for ARM PAC in DWARF info
    fn check_arm_pac(dwarf: &DwarfInfo) -> ArmPacResult {
        if !dwarf.has_debug_info {
            return ArmPacResult::NoDwarf;
        }

        // Check for -mbranch-protection flags in producer strings
        for cu in &dwarf.compilation_units {
            let producer = &cu.compiler_info.producer;

            // -mbranch-protection=standard enables both PAC and BTI
            if producer.contains("-mbranch-protection=standard") {
                return ArmPacResult::Enabled;
            }

            // -mbranch-protection=pac-ret enables PAC specifically
            if producer.contains("-mbranch-protection=pac-ret") {
                return ArmPacResult::Enabled;
            }

            // Check for pac-ret in combined options like -mbranch-protection=pac-ret+bti
            if producer.contains("pac-ret") {
                return ArmPacResult::Enabled;
            }
        }

        ArmPacResult::Disabled
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArmPacResult {
    Enabled,
    Disabled,
    NoDwarf,
}

impl Default for PeEnableArmPAC {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for PeEnableArmPAC {
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

        // Only applicable to ARM64 PE binaries
        if !pe.is_arm64() {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Not an ARM64 binary".to_string()),
            );
        }

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

        // Check DWARF producer strings for ARM PAC flags
        match Self::check_arm_pac(&dwarf) {
            ArmPacResult::Enabled => {
                self.log_pass(context, "Pass", &[&file_name]);
            }
            ArmPacResult::Disabled => {
                self.log_fail(context, FailureLevel::Warning, "Warning", &[&file_name]);
            }
            ArmPacResult::NoDwarf => {
                self.log_not_applicable(context, "NotApplicable_NoDwarf", &[&file_name]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_descriptor() {
        let rule = PeEnableArmPAC::new();
        assert_eq!(rule.descriptor().id, "AD2039");
        assert_eq!(rule.descriptor().name, "PeEnableArmPAC");
        assert_eq!(rule.descriptor().category, RuleCategory::Security);
    }
}
