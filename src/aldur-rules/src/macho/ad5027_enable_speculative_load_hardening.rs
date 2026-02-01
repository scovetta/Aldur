//! AD5027: EnableSpeculativeLoadHardeningMachO
//!
//! Verifies speculative load hardening is enabled (Clang -mspeculative-load-hardening).
//! This mitigation helps protect against Spectre variant 1 attacks.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{DwarfInfo, MachOBinary};

use crate::rule_ids::AD5027;

pub struct EnableSpeculativeLoadHardeningMachO {
    descriptor: RuleDescriptor,
}

impl EnableSpeculativeLoadHardeningMachO {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD5027, "EnableSpeculativeLoadHardeningMachO")
            .with_category(RuleCategory::Security)
            .with_tags(&["hardening", "memory-safety", "macos-only", "intel-only"])
            .with_short_description("Enable speculative load hardening for Mach-O binaries.")
            .with_full_description(
                "Speculative load hardening (-mspeculative-load-hardening) is a Clang/LLVM \
                 mitigation that helps protect against Spectre variant 1 attacks. It works \
                 by inserting instructions that mask the result of conditional branches, \
                 preventing speculative execution from accessing sensitive data. This \
                 mitigation has a performance cost but provides strong protection for \
                 security-sensitive code paths.",
            )
            .with_fix_hint("Compile with -mspeculative-load-hardening (Clang only)")
            .with_default_level(FailureLevel::Note)
            .with_message(
                "Pass",
                "Speculative load hardening is enabled on '{0}'.",
            )
            .with_message(
                "Pass_DwarfConfirmed",
                "Speculative load hardening is enabled on '{0}' (confirmed via DWARF debug info).",
            )
            .with_message(
                "Note_NoSLH",
                "Speculative load hardening is not enabled on '{0}'. For security-sensitive \
                 code that processes secrets or untrusted input, consider compiling with \
                 '-mspeculative-load-hardening' to mitigate Spectre variant 1 attacks.",
            )
            .with_message(
                "Note_Heuristic",
                "Speculative load hardening may not be enabled on '{0}'. Consider compiling with \
                 '-mspeculative-load-hardening' for Spectre protection.",
            )
            .with_message(
                "NotApplicable_NotX86",
                "'{0}' is not an x86/x86_64 binary. Speculative load hardening is currently \
                 only supported on x86 architectures.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }

    /// Check for indicators of speculative load hardening
    fn check_slh(macho: &MachOBinary) -> (bool, bool) {
        // Try to get definitive answer from DWARF debug info
        if let Ok(dwarf_info) = DwarfInfo::parse(macho.data()) {
            if dwarf_info.has_debug_info && !dwarf_info.compilation_units.is_empty() {
                // Check if -mspeculative-load-hardening flag is present
                let has_slh = dwarf_info.has_flag("-mspeculative-load-hardening")
                    || dwarf_info.has_flag("speculative-load-hardening");
                let explicitly_disabled =
                    dwarf_info.has_flag("-mno-speculative-load-hardening");

                if has_slh && !explicitly_disabled {
                    return (true, true); // (has_slh, is_definitive)
                } else if explicitly_disabled {
                    return (false, true);
                }
            }
        }

        // Heuristic: SLH adds specific patterns that are hard to detect without disassembly
        let slh_symbols = &[
            "__llvm_slh_",
            "__x86_indirect_thunk",
            "__x86_return_thunk",
        ];
        let has_symbol = macho.has_any_symbol(slh_symbols);

        (has_symbol, false) // (has_slh, is_definitive=false for heuristic)
    }
}

impl Default for EnableSpeculativeLoadHardeningMachO {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableSpeculativeLoadHardeningMachO {
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

        // SLH is only supported on x86/x86_64 - check primary architecture
        let is_x86 = macho.primary_arch().map(|a| {
            use aldur_parsers::macho::cpu_type;
            a.cpu_type == cpu_type::CPU_TYPE_X86_64 || a.cpu_type == cpu_type::CPU_TYPE_I386
        }).unwrap_or(false);

        if !is_x86 {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Not an x86/x86_64 binary".to_string()),
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

        // Only applicable to x86/x86_64
        let is_x86 = macho.primary_arch().map(|a| {
            use aldur_parsers::macho::cpu_type;
            a.cpu_type == cpu_type::CPU_TYPE_X86_64 || a.cpu_type == cpu_type::CPU_TYPE_I386
        }).unwrap_or(false);

        if !is_x86 {
            self.log_not_applicable(context, "NotApplicable_NotX86", &[&file_name]);
            return;
        }

        let (has_slh, is_definitive) = Self::check_slh(macho);

        if has_slh {
            if is_definitive {
                self.log_pass(context, "Pass_DwarfConfirmed", &[&file_name]);
            } else {
                self.log_pass(context, "Pass", &[&file_name]);
            }
        } else if is_definitive {
            self.log_fail(
                context,
                FailureLevel::Note,
                "Note_NoSLH",
                &[&file_name],
            );
        } else {
            self.log_fail(
                context,
                FailureLevel::Note,
                "Note_Heuristic",
                &[&file_name],
            );
        }
    }
}
