//! AD3005: EnableStackClashProtection
//!
//! Verifies stack clash protection is enabled (GCC/Clang -fstack-clash-protection).
//! Stack clash protection prevents the stack from "clashing" with other memory regions.
//! Note: This is a GCC/Clang feature and is not applicable to Rust or Go binaries.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{DwarfInfo, ElfBinary};

use crate::elf::compiler_utils::{check_compiler_support, detect_compiler, CompilerFeature};
use crate::rule_ids::AD3005;

pub struct EnableStackClashProtection {
    descriptor: RuleDescriptor,
}

impl EnableStackClashProtection {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD3005, "EnableStackClashProtection")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "memory-safety", "rhel-annocheck", "openssf"])
            .with_short_description("Enable stack clash protection.")
            .with_full_description(
                "Stack clash protection prevents the stack from 'clashing' with other memory \
                 regions (like the heap) by probing stack pages as they are allocated. This \
                 prevents attackers from using large stack allocations to skip over guard pages. \
                 Compile with '-fstack-clash-protection' to enable.",
            )
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "Stack clash protection is enabled on '{0}'.",
            )
            .with_message(
                "Pass_DwarfConfirmed",
                "Stack clash protection is enabled on '{0}' (confirmed via DWARF debug info).",
            )
            .with_message(
                "Warning",
                "Stack clash protection is not enabled on '{0}'. Compile with \
                 '-fstack-clash-protection' to enable this protection.",
            )
            .with_message(
                "Warning_Heuristic",
                "Stack clash protection may not be enabled on '{0}'. Consider compiling with \
                 '-fstack-clash-protection' to enable this protection.",
            )
            .with_message(
                "NotApplicable_UnsupportedCompiler",
                "'{0}' was compiled with {1}. Stack clash protection (-fstack-clash-protection) is a GCC/Clang feature.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            )
            .with_fix_hint("Compile with -fstack-clash-protection (GCC 8+, Clang 11+).");

        Self { descriptor }
    }

    /// Check for indicators of stack clash protection
    fn check_stack_clash_protection(elf: &ElfBinary) -> (bool, bool) {
        // First, try to get definitive answer from DWARF debug info
        if let Ok(dwarf_info) = DwarfInfo::parse(elf.data()) {
            if dwarf_info.has_debug_info && !dwarf_info.compilation_units.is_empty() {
                // Check if -fstack-clash-protection flag is present
                let has_protection = dwarf_info.has_flag("-fstack-clash-protection");
                let explicitly_disabled = dwarf_info.has_flag("-fno-stack-clash-protection");

                if has_protection && !explicitly_disabled {
                    return (true, true); // (has_protection, is_definitive)
                } else if explicitly_disabled {
                    return (false, true);
                }
                // If we have DWARF but no flag, assume not enabled (many producers don't embed flags)
            }
        }

        // Fallback: Look for __probestack which is used by some implementations
        // This is a heuristic - full detection would require disassembly
        let probe_symbols = &["__probestack", "__rust_probestack"];
        let has_symbol = elf.has_any_symbol(probe_symbols);

        (has_symbol, false) // (has_protection, is_definitive=false for heuristic)
    }
}

impl Default for EnableStackClashProtection {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableStackClashProtection {
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

        // Stack clash protection is a GCC/Clang feature - skip unsupported compilers
        let compiler = detect_compiler(elf);
        if let Some(reason) =
            check_compiler_support(&compiler, CompilerFeature::StackClashProtection)
        {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some(reason),
            );
        }

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

        let (has_protection, is_definitive) = Self::check_stack_clash_protection(elf);

        if has_protection {
            if is_definitive {
                self.log_pass(context, "Pass_DwarfConfirmed", &[&file_name]);
            } else {
                self.log_pass(context, "Pass", &[&file_name]);
            }
        } else if is_definitive {
            self.log_fail(context, FailureLevel::Warning, "Warning", &[&file_name]);
        } else {
            self.log_fail(
                context,
                FailureLevel::Warning,
                "Warning_Heuristic",
                &[&file_name],
            );
        }
    }
}
