//! AD3043: EnableKernelCFI
//!
//! Verifies Kernel Control Flow Integrity (KCFI) is enabled for kernel/embedded binaries.
//! KCFI is a lightweight CFI implementation that doesn't require LTO.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{DwarfInfo, ElfBinary};

use crate::rule_ids::AD3043;

pub struct EnableKernelCFI {
    descriptor: RuleDescriptor,
}

impl EnableKernelCFI {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD3043, "EnableKernelCFI")
            .with_category(RuleCategory::Security)
            .with_tags(&["hardening", "control-flow", "linux-only"])
            .with_short_description(
                "Enable Kernel Control Flow Integrity (KCFI) for kernel and embedded binaries.",
            )
            .with_full_description(
                "Kernel Control Flow Integrity (KCFI) is a lightweight CFI implementation \
                 designed for kernel and embedded environments. Unlike regular CFI, KCFI does \
                 not require Link-Time Optimization (LTO), preserves function pointer equality, \
                 and doesn't use jump tables. KCFI validates indirect calls by checking type \
                 hashes embedded before each function. Enable with '-fsanitize=kcfi' (Clang) \
                 or '-fcf-protection=branch' with kernel patches (GCC). KCFI is used by the \
                 Linux kernel and Android for kernel-level protection.",
            )
            .with_fix_hint("Compile with -fsanitize=kcfi (Clang only)")
            .with_default_level(FailureLevel::Note)
            .with_message(
                "Pass",
                "'{0}' has Kernel Control Flow Integrity (KCFI) enabled.",
            )
            .with_message(
                "Pass_KcfiSymbols",
                "'{0}' has KCFI symbols present, indicating KCFI is enabled.",
            )
            .with_message(
                "Pass_DwarfConfirmed",
                "'{0}' has KCFI enabled (confirmed via DWARF debug info).",
            )
            .with_message(
                "Note_NoKcfi",
                "'{0}' does not have Kernel Control Flow Integrity (KCFI) enabled. For \
                 kernel or embedded binaries compiled with Clang, consider using \
                 '-fsanitize=kcfi' to enable lightweight CFI without requiring LTO.",
            )
            .with_message(
                "NotApplicable_NotKernel",
                "'{0}' does not appear to be a kernel or embedded binary. KCFI is typically \
                 used for kernel-level code. Consider using '-fsanitize=cfi' instead.",
            )
            .with_message(
                "NotApplicable_RustBinary",
                "'{0}' is a Rust binary. KCFI (-fsanitize=kcfi) is a Clang feature. For Rust, \
                 use '-Zsanitizer=kcfi' on nightly (see AD3037 RustEnableSanitizers).",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }

    /// KCFI-related symbols that indicate KCFI is enabled
    const KCFI_SYMBOLS: &'static [&'static str] = &[
        "__kcfi_typeid",
        "__cfi_check",
        ".kcfi",
        "__kcfi",
        "kcfi_trap",
    ];

    /// Symbols that indicate this might be a kernel or embedded binary
    const KERNEL_INDICATORS: &'static [&'static str] = &[
        "start_kernel",
        "vmlinux",
        "_stext",
        "_etext",
        "init_task",
        "__start___ksymtab",
        "kernel_init",
        "do_initcalls",
        "printk",
        "panic",
    ];

    /// Check for KCFI via symbols
    fn has_kcfi_symbols(elf: &ElfBinary) -> bool {
        elf.has_any_symbol(Self::KCFI_SYMBOLS)
    }

    /// Check if this appears to be a kernel binary
    fn is_kernel_binary(elf: &ElfBinary) -> bool {
        // Check for kernel-specific symbols
        if elf.has_any_symbol(Self::KERNEL_INDICATORS) {
            return true;
        }

        // Check for kernel-specific sections
        if elf.has_section(".modinfo") || elf.has_section("__ksymtab") {
            return true;
        }

        // Check if it's statically linked (kernels typically are)
        // by looking for absence of dynamic section
        if !elf.has_section(".dynamic") && !elf.has_section(".interp") {
            // Could be a kernel or embedded binary
            return true;
        }

        false
    }

    /// Check DWARF for KCFI flags
    fn check_dwarf_for_kcfi(dwarf: &DwarfInfo) -> (bool, bool) {
        let mut is_clang_or_gcc = false;
        let mut has_kcfi = false;

        for cu in &dwarf.compilation_units {
            // Check if compiled with Clang or GCC
            let compiler_type = &cu.parsed_info.compiler_type;
            if matches!(
                compiler_type,
                aldur_parsers::dwarf::CompilerType::Clang | aldur_parsers::dwarf::CompilerType::Gcc
            ) {
                is_clang_or_gcc = true;
            }

            // Check for KCFI flags in producer or command line
            let producer = &cu.compiler_info.producer;
            if producer.contains("-fsanitize=kcfi") || producer.contains("sanitize=kcfi") {
                has_kcfi = true;
            }

            // Check individual flags
            for flag in &cu.parsed_info.flags {
                if flag.contains("sanitize=kcfi") || flag == "-fsanitize=kcfi" {
                    has_kcfi = true;
                }
            }
        }

        (is_clang_or_gcc, has_kcfi)
    }
}

impl Default for EnableKernelCFI {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableKernelCFI {
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

        // Rust binaries should use AD3037 RustEnableSanitizers for KCFI on nightly
        if elf.is_rust_binary {
            self.log_not_applicable(context, "NotApplicable_RustBinary", &[&file_name]);
            return;
        }

        // First, check for KCFI symbols (most reliable indicator)
        if Self::has_kcfi_symbols(elf) {
            self.log_pass(context, "Pass_KcfiSymbols", &[&file_name]);
            return;
        }

        // Try DWARF debug info for more details
        let dwarf_result = DwarfInfo::parse(elf.data());

        if let Ok(ref dwarf) = dwarf_result {
            if dwarf.has_debug_info {
                let (is_clang_or_gcc, has_kcfi) = Self::check_dwarf_for_kcfi(dwarf);

                if has_kcfi {
                    self.log_pass(context, "Pass_DwarfConfirmed", &[&file_name]);
                    return;
                }

                // Only suggest KCFI for kernel/embedded binaries
                if !Self::is_kernel_binary(elf) && is_clang_or_gcc {
                    self.log_not_applicable(context, "NotApplicable_NotKernel", &[&file_name]);
                    return;
                }
            }
        }

        // Check if this is a kernel binary that should have KCFI
        if Self::is_kernel_binary(elf) {
            self.log_fail(context, FailureLevel::Note, "Note_NoKcfi", &[&file_name]);
        } else {
            // Not a kernel binary, KCFI not applicable
            self.log_not_applicable(context, "NotApplicable_NotKernel", &[&file_name]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableKernelCFI::new();
        assert_eq!(rule.descriptor().id, "AD3043");
        assert_eq!(rule.descriptor().name, "EnableKernelCFI");
        assert_eq!(rule.descriptor().category, RuleCategory::Security);
    }
}
