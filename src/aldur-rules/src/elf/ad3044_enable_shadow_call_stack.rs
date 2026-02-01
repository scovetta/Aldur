//! AD3044: EnableShadowCallStack
//!
//! Verifies Shadow Call Stack (SCS) is enabled for AArch64 binaries.
//! SCS provides strong return address protection by storing return addresses
//! in a separate shadow stack.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{DwarfInfo, ElfBinary};

use crate::rule_ids::AD3044;

pub struct EnableShadowCallStack {
    descriptor: RuleDescriptor,
}

impl EnableShadowCallStack {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD3044, "EnableShadowCallStack")
            .with_category(RuleCategory::Security)
            .with_tags(&["hardening", "control-flow", "linux-only", "arm-only"])
            .with_short_description(
                "Enable Shadow Call Stack (SCS) for AArch64 binaries to protect return addresses.",
            )
            .with_full_description(
                "Shadow Call Stack (SCS) is a security feature that protects return addresses \
                 by storing them in a separate 'shadow' stack. This prevents Return-Oriented \
                 Programming (ROP) attacks that rely on overwriting return addresses. SCS uses \
                 a dedicated register (x18 on AArch64) to point to the shadow stack. Enable with \
                 '-fsanitize=shadow-call-stack' (Clang/GCC). SCS is production-ready and used by \
                 Android. Note: Requires AArch64 or RISC-V architecture.",
            )
            .with_fix_hint("Compile with -fsanitize=shadow-call-stack (AArch64/RISC-V only)")
            .with_default_level(FailureLevel::Note)
            .with_message(
                "Pass",
                "'{0}' has Shadow Call Stack (SCS) enabled for return address protection.",
            )
            .with_message(
                "Pass_ScsSymbols",
                "'{0}' has SCS symbols present, indicating Shadow Call Stack is enabled.",
            )
            .with_message(
                "Pass_DwarfConfirmed",
                "'{0}' has Shadow Call Stack enabled (confirmed via DWARF debug info).",
            )
            .with_message(
                "Note_NoScs",
                "'{0}' does not have Shadow Call Stack (SCS) enabled. For AArch64 binaries, \
                 consider compiling with '-fsanitize=shadow-call-stack' to protect return \
                 addresses from ROP attacks.",
            )
            .with_message(
                "NotApplicable_NotAArch64",
                "'{0}' is not an AArch64 or RISC-V binary. Shadow Call Stack is only \
                 available on these architectures.",
            )
            .with_message(
                "NotApplicable_RustBinary",
                "'{0}' is a Rust binary. Shadow Call Stack (-fsanitize=shadow-call-stack) is a \
                 Clang feature. For Rust, use '-Zsanitizer=shadow-call-stack' on nightly \
                 (see AD3037 RustEnableSanitizers).",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }

    /// SCS-related symbols that indicate SCS is enabled
    const SCS_SYMBOLS: &'static [&'static str] = &[
        "__shadow_call_stack",
        "__scs_overflow",
        "__scs_init",
        ".shadow_call_stack",
        "__builtin_shadow_call_stack",
    ];

    /// Check for SCS via symbols
    fn has_scs_symbols(elf: &ElfBinary) -> bool {
        elf.has_any_symbol(Self::SCS_SYMBOLS)
    }

    /// Check if this is an AArch64 or RISC-V binary (SCS supported architectures)
    fn is_scs_supported_arch(elf: &ElfBinary) -> bool {
        // AArch64 is EM_AARCH64 (0xB7), RISC-V is EM_RISCV (0xF3)
        elf.is_aarch64() || elf.machine == 0xF3
    }

    /// Check DWARF for SCS flags
    fn check_dwarf_for_scs(dwarf: &DwarfInfo) -> (bool, bool) {
        let mut is_clang_or_gcc = false;
        let mut has_scs = false;

        for cu in &dwarf.compilation_units {
            // Check if compiled with Clang or GCC
            let compiler_type = &cu.parsed_info.compiler_type;
            if matches!(
                compiler_type,
                aldur_parsers::dwarf::CompilerType::Clang
                    | aldur_parsers::dwarf::CompilerType::Gcc
            ) {
                is_clang_or_gcc = true;
            }

            // Check for SCS flags in producer or command line
            let producer = &cu.compiler_info.producer;
            if producer.contains("-fsanitize=shadow-call-stack")
                || producer.contains("sanitize=shadow-call-stack")
            {
                has_scs = true;
            }

            // Check individual flags
            for flag in &cu.parsed_info.flags {
                if flag.contains("sanitize=shadow-call-stack")
                    || flag == "-fsanitize=shadow-call-stack"
                {
                    has_scs = true;
                }
            }
        }

        (is_clang_or_gcc, has_scs)
    }
}

impl Default for EnableShadowCallStack {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableShadowCallStack {
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

        // Check if this is an SCS-supported architecture
        if !Self::is_scs_supported_arch(elf) {
            self.log_not_applicable(context, "NotApplicable_NotAArch64", &[&file_name]);
            return;
        }

        // Rust binaries should use AD3037 RustEnableSanitizers for SCS on nightly
        if elf.is_rust_binary {
            self.log_not_applicable(context, "NotApplicable_RustBinary", &[&file_name]);
            return;
        }

        // First, check for SCS symbols (most reliable indicator)
        if Self::has_scs_symbols(elf) {
            self.log_pass(context, "Pass_ScsSymbols", &[&file_name]);
            return;
        }

        // Try DWARF debug info for more details
        let dwarf_result = DwarfInfo::parse(elf.data());

        if let Ok(ref dwarf) = dwarf_result {
            if dwarf.has_debug_info {
                let (_is_clang_or_gcc, has_scs) = Self::check_dwarf_for_scs(dwarf);

                if has_scs {
                    self.log_pass(context, "Pass_DwarfConfirmed", &[&file_name]);
                    return;
                }
            }
        }

        // SCS not detected
        self.log_fail(context, FailureLevel::Note, "Note_NoScs", &[&file_name]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableShadowCallStack::new();
        assert_eq!(rule.descriptor().id, "AD3044");
        assert_eq!(rule.descriptor().name, "EnableShadowCallStack");
        assert_eq!(rule.descriptor().category, RuleCategory::Security);
    }
}
