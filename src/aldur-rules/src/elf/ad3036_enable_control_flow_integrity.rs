//! AD3036: EnableControlFlowIntegrity
//!
//! Verifies Control Flow Integrity (CFI) is enabled for Clang/LLVM binaries.
//! CFI is enabled with -fsanitize=cfi and requires LTO (-flto).
//! Note: This is a Clang-only feature. Rust binaries on nightly can use -Z sanitizer=cfi.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{DwarfInfo, ElfBinary};

use crate::elf::compiler_utils::{CompilerFeature, check_compiler_support, detect_compiler};
use crate::rule_ids::AD3036;

pub struct EnableControlFlowIntegrity {
    descriptor: RuleDescriptor,
}

impl EnableControlFlowIntegrity {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD3036, "EnableControlFlowIntegrity")
            .with_category(RuleCategory::Security)
            .with_tags(&["hardening", "control-flow", "linux-only", "openssf"])
            .with_short_description("Enable Control Flow Integrity (CFI) for Clang binaries.")
            .with_full_description(
                "Control Flow Integrity (CFI) is a Clang/LLVM security feature that helps \
                 prevent control-flow hijacking attacks. CFI validates that indirect calls \
                 and jumps target valid locations based on static type information. \
                 Enable with '-flto -fsanitize=cfi' or '-flto=thin -fsanitize=cfi'. \
                 For shared libraries, use '-fsanitize-cfi-cross-dso'. Adding \
                 '-fwhole-program-vtables' further enhances CFI by enabling whole-program \
                 vtable optimizations and reducing the attack surface through devirtualization.",
            )
            .with_fix_hint("Compile with -flto -fsanitize=cfi (Clang only)")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' has Control Flow Integrity (CFI) enabled.",
            )
            .with_message(
                "Pass_CfiSymbols",
                "'{0}' has CFI symbols present, indicating CFI is enabled.",
            )
            .with_message(
                "Pass_DwarfConfirmed",
                "'{0}' has CFI enabled (confirmed via DWARF debug info).",
            )
            .with_message(
                "Warning_NoCfi",
                "'{0}' does not have Control Flow Integrity (CFI) enabled. For Clang/LLVM \
                 binaries, consider compiling with '-flto -fsanitize=cfi -fwhole-program-vtables' \
                 to enable CFI with enhanced vtable protection.",
            )
            .with_message(
                "Warning_LtoWithoutCfi",
                "'{0}' has LTO enabled but not CFI. Consider adding '-fsanitize=cfi \
                 -fwhole-program-vtables' to enable Control Flow Integrity with enhanced vtable protection.",
            )
            .with_message(
                "NotApplicable_NotClang",
                "'{0}' was not compiled with Clang/LLVM. CFI is a Clang-specific feature.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }

    /// CFI-related symbols that indicate CFI is enabled
    const CFI_SYMBOLS: &'static [&'static str] = &[
        "__cfi_check",
        "__cfi_slowpath",
        "__cfi_slowpath_diag",
        "__ubsan_handle_cfi",
        "__cfi_init",
        ".cfi_jt",
    ];

    /// LTO-related symbols/sections that indicate LTO is enabled
    const LTO_INDICATORS: &'static [&'static str] = &[".llvm.lto", "__llvm_prf", "__llvm_coverage"];

    /// Check for CFI via symbols
    fn has_cfi_symbols(elf: &ElfBinary) -> bool {
        elf.has_any_symbol(Self::CFI_SYMBOLS)
    }

    /// Check for LTO via symbols/sections
    fn has_lto_indicators(elf: &ElfBinary) -> bool {
        // Check for LTO-related symbols
        if elf.has_any_symbol(Self::LTO_INDICATORS) {
            return true;
        }

        // Check for LTO sections
        if elf.has_section(".llvm.lto") || elf.has_section(".gnu.lto_") {
            return true;
        }

        false
    }

    /// Check DWARF for CFI flags
    fn check_dwarf_for_cfi(dwarf: &DwarfInfo) -> (bool, bool, bool) {
        let mut is_clang = false;
        let mut has_lto = false;
        let mut has_cfi = false;

        for cu in &dwarf.compilation_units {
            // Check if compiled with Clang
            if cu.parsed_info.compiler_type == aldur_parsers::dwarf::CompilerType::Clang {
                is_clang = true;
            }

            // Check for LTO flag
            if cu.parsed_info.has_lto {
                has_lto = true;
            }

            // Check for CFI flags in producer or command line
            let producer = &cu.compiler_info.producer;
            if producer.contains("-fsanitize=cfi") || producer.contains("sanitize=cfi") {
                has_cfi = true;
            }

            // Check individual flags
            for flag in &cu.parsed_info.flags {
                if flag.contains("sanitize=cfi") || flag == "-fsanitize=cfi" {
                    has_cfi = true;
                }
            }
        }

        (is_clang, has_lto, has_cfi)
    }
}

impl Default for EnableControlFlowIntegrity {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableControlFlowIntegrity {
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

        // CFI is a Clang-only feature - skip non-Clang binaries
        let compiler = detect_compiler(elf);
        if let Some(reason) = check_compiler_support(&compiler, CompilerFeature::ClangCFI) {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some(reason),
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

        // First, check for CFI symbols (most reliable indicator)
        if Self::has_cfi_symbols(elf) {
            self.log_pass(context, "Pass_CfiSymbols", &[&file_name]);
            return;
        }

        // Try DWARF debug info for more details
        let dwarf_result = DwarfInfo::parse(elf.data());

        if let Ok(ref dwarf) = dwarf_result {
            if dwarf.has_debug_info {
                let (is_clang, has_lto, has_cfi) = Self::check_dwarf_for_cfi(dwarf);

                // Not a Clang binary - CFI is Clang-specific
                if !is_clang {
                    // Check if it's a Rust binary (Rust uses LLVM backend)
                    if !elf.is_rust_binary {
                        self.log_not_applicable(context, "NotApplicable_NotClang", &[&file_name]);
                        return;
                    }
                }

                if has_cfi {
                    self.log_pass(context, "Pass_DwarfConfirmed", &[&file_name]);
                    return;
                }

                if has_lto {
                    // Has LTO but no CFI - could enable CFI
                    self.log_fail(
                        context,
                        FailureLevel::Warning,
                        "Warning_LtoWithoutCfi",
                        &[&file_name],
                    );
                    return;
                }
            }
        }

        // Check for LTO indicators without DWARF
        let has_lto = Self::has_lto_indicators(elf)
            || dwarf_result.as_ref().map(|d| d.has_lto()).unwrap_or(false);

        if has_lto {
            self.log_fail(
                context,
                FailureLevel::Warning,
                "Warning_LtoWithoutCfi",
                &[&file_name],
            );
        } else {
            // Without DWARF info and no CFI symbols, we can't determine compiler
            // Issue a general warning about CFI
            self.log_fail(
                context,
                FailureLevel::Warning,
                "Warning_NoCfi",
                &[&file_name],
            );
        }
    }
}
