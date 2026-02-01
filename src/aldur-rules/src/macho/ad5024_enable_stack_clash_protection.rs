//! AD5024: EnableStackClashProtectionMachO
//!
//! Verifies stack clash protection is enabled for Mach-O binaries.
//! Stack clash protection prevents the stack from "clashing" with other memory regions.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{DwarfInfo, MachOBinary};

use crate::rule_ids::AD5024;

pub struct EnableStackClashProtectionMachO {
    descriptor: RuleDescriptor,
}

impl EnableStackClashProtectionMachO {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD5024, "EnableStackClashProtectionMachO")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "memory-safety", "macos-only", "openssf"])
            .with_short_description("Enable stack clash protection for Mach-O binaries.")
            .with_full_description(
                "Stack clash protection prevents the stack from 'clashing' with other memory \
                 regions (like the heap) by probing stack pages as they are allocated. This \
                 prevents attackers from using large stack allocations to skip over guard pages. \
                 Compile with '-fstack-clash-protection' to enable. Note: Apple's Clang may not \
                 support this flag on all platforms.",
            )
            .with_fix_hint("Compile with -fstack-clash-protection")
            .with_default_level(FailureLevel::Note)
            .with_message("Pass", "Stack clash protection is enabled on '{0}'.")
            .with_message(
                "Pass_DwarfConfirmed",
                "Stack clash protection is enabled on '{0}' (confirmed via DWARF debug info).",
            )
            .with_message(
                "Note",
                "Stack clash protection is not enabled on '{0}'. If using a Clang version that \
                 supports it, consider compiling with '-fstack-clash-protection'.",
            )
            .with_message(
                "Note_Heuristic",
                "Stack clash protection may not be enabled on '{0}'. Consider compiling with \
                 '-fstack-clash-protection' if your toolchain supports it.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }

    /// Check for indicators of stack clash protection
    fn check_stack_clash_protection(macho: &MachOBinary) -> (bool, bool) {
        // Try to get definitive answer from DWARF debug info
        if let Ok(dwarf_info) = DwarfInfo::parse(macho.data()) {
            if dwarf_info.has_debug_info && !dwarf_info.compilation_units.is_empty() {
                // Check if -fstack-clash-protection flag is present
                let has_protection = dwarf_info.has_flag("-fstack-clash-protection");
                let explicitly_disabled = dwarf_info.has_flag("-fno-stack-clash-protection");

                if has_protection && !explicitly_disabled {
                    return (true, true); // (has_protection, is_definitive)
                } else if explicitly_disabled {
                    return (false, true);
                }
            }
        }

        // Fallback: Look for __probestack which is used by some implementations
        let probe_symbols = &["__probestack", "__rust_probestack"];
        let has_symbol = macho.has_any_symbol(probe_symbols);

        (has_symbol, false) // (has_protection, is_definitive=false for heuristic)
    }
}

impl Default for EnableStackClashProtectionMachO {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableStackClashProtectionMachO {
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

        let (has_protection, is_definitive) = Self::check_stack_clash_protection(macho);

        if has_protection {
            if is_definitive {
                self.log_pass(context, "Pass_DwarfConfirmed", &[&file_name]);
            } else {
                self.log_pass(context, "Pass", &[&file_name]);
            }
        } else if is_definitive {
            self.log_fail(context, FailureLevel::Note, "Note", &[&file_name]);
        } else {
            self.log_fail(context, FailureLevel::Note, "Note_Heuristic", &[&file_name]);
        }
    }
}
