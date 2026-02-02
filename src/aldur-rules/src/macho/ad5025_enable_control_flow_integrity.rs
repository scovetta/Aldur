//! AD5025: EnableControlFlowIntegrityMachO
//!
//! Verifies Control Flow Integrity (CFI) is enabled for Clang/LLVM Mach-O binaries.
//! CFI is enabled with -fsanitize=cfi and requires LTO (-flto).

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{DwarfInfo, MachOBinary};

use crate::rule_ids::AD5025;

pub struct EnableControlFlowIntegrityMachO {
    descriptor: RuleDescriptor,
}

impl EnableControlFlowIntegrityMachO {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD5025, "EnableControlFlowIntegrityMachO")
            .with_category(RuleCategory::Security)
            .with_tags(&["hardening", "control-flow", "macos-only", "openssf"])
            .with_short_description("Enable Control Flow Integrity (CFI) for Mach-O binaries.")
            .with_full_description(
                "Control Flow Integrity (CFI) is a Clang/LLVM security feature that helps \
                 prevent control-flow hijacking attacks. CFI validates that indirect calls \
                 and jumps target valid locations based on static type information. \
                 Enable with '-flto -fsanitize=cfi' when compiling with Clang. Apple's \
                 compiler may also use CFI internally for certain security features.",
            )
            .with_fix_hint("Compile with -flto -fsanitize=cfi (Clang only)")
            .with_default_level(FailureLevel::Note)
            .with_message("Pass", "'{0}' has Control Flow Integrity (CFI) enabled.")
            .with_message(
                "Pass_CfiSymbols",
                "'{0}' has CFI symbols present, indicating CFI is enabled.",
            )
            .with_message(
                "Pass_DwarfConfirmed",
                "'{0}' has CFI enabled (confirmed via DWARF debug info).",
            )
            .with_message(
                "Note_NoCfi",
                "'{0}' does not have Control Flow Integrity (CFI) enabled. For security-sensitive \
                 applications, consider compiling with '-flto -fsanitize=cfi' to enable CFI.",
            )
            .with_message(
                "Note_LtoWithoutCfi",
                "'{0}' has LTO enabled but not CFI. Consider adding '-fsanitize=cfi' \
                 to enable Control Flow Integrity protection.",
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
    ];

    /// Check for CFI via symbols
    fn has_cfi_symbols(macho: &MachOBinary) -> bool {
        macho.has_any_symbol(Self::CFI_SYMBOLS)
    }

    /// Check DWARF for CFI flags
    fn check_dwarf_for_cfi(macho: &MachOBinary) -> (bool, bool) {
        if let Ok(dwarf_info) = DwarfInfo::parse(macho.data())
            && dwarf_info.has_debug_info
            && !dwarf_info.compilation_units.is_empty()
        {
            let has_cfi =
                dwarf_info.has_flag("-fsanitize=cfi") || dwarf_info.has_flag("sanitize=cfi");
            let has_lto = dwarf_info.has_flag("-flto");

            return (has_cfi, has_lto);
        }
        (false, false)
    }
}

impl Default for EnableControlFlowIntegrityMachO {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableControlFlowIntegrityMachO {
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

        // Check for CFI symbols first (most reliable)
        if Self::has_cfi_symbols(macho) {
            self.log_pass(context, "Pass_CfiSymbols", &[&file_name]);
            return;
        }

        // Check DWARF for CFI flags
        let (has_cfi, has_lto) = Self::check_dwarf_for_cfi(macho);

        if has_cfi {
            self.log_pass(context, "Pass_DwarfConfirmed", &[&file_name]);
        } else if has_lto {
            // Has LTO but not CFI - could add CFI
            self.log_fail(
                context,
                FailureLevel::Note,
                "Note_LtoWithoutCfi",
                &[&file_name],
            );
        } else {
            self.log_fail(context, FailureLevel::Note, "Note_NoCfi", &[&file_name]);
        }
    }
}
