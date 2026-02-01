//! AD2036: PeEnableControlFlowIntegrity
//!
//! Checks for Clang Control Flow Integrity (CFI) in PE binaries with DWARF debug info.
//! CFI helps prevent control-flow hijacking attacks by validating indirect calls.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, Binary, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{DwarfInfo, PeBinary};

use crate::rule_ids::AD2036;

pub struct PeEnableControlFlowIntegrity {
    descriptor: RuleDescriptor,
}

impl PeEnableControlFlowIntegrity {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2036, "PeEnableControlFlowIntegrity")
            .with_category(RuleCategory::Security)
            .with_tags(&["hardening", "control-flow", "windows-only", "openssf"])
            .with_short_description(
                "Enable Control Flow Integrity (CFI) for PE binaries built with Clang.",
            )
            .with_full_description(
                "PE binaries built with Clang should enable Control Flow Integrity (CFI) \
                 to prevent control-flow hijacking attacks. CFI validates that indirect \
                 calls and jumps target valid locations based on static type information. \
                 Enable with '-flto -fsanitize=cfi' or '-flto=thin -fsanitize=cfi'. \
                 For shared libraries, use '-fsanitize-cfi-cross-dso'. Adding \
                 '-fwhole-program-vtables' further enhances CFI by enabling whole-program \
                 vtable optimizations and reducing the attack surface through devirtualization. \
                 This rule checks for CFI symbols or -fsanitize=cfi flags in DWARF debug information.",
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
                "'{0}' does not have Control Flow Integrity (CFI) enabled. For Clang \
                 binaries, consider compiling with '-flto -fsanitize=cfi -fwhole-program-vtables' \
                 to enable CFI with enhanced vtable protection.",
            )
            .with_message(
                "Warning_LtoWithoutCfi",
                "'{0}' has LTO enabled but not CFI. Consider adding '-fsanitize=cfi \
                 -fwhole-program-vtables' to enable Control Flow Integrity with enhanced vtable protection.",
            )
            .with_message(
                "NotApplicable_NoDwarf",
                "'{0}' does not contain DWARF debug information.",
            )
            .with_message(
                "NotApplicable_NotClang",
                "'{0}' was not compiled with Clang. CFI is a Clang-specific feature.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}': {2}.",
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

    /// Check for CFI symbols in DWARF info
    fn has_cfi_symbols(dwarf: &DwarfInfo) -> bool {
        for cu in &dwarf.compilation_units {
            let producer = &cu.compiler_info.producer;
            for symbol in Self::CFI_SYMBOLS {
                if producer.contains(symbol) {
                    return true;
                }
            }
        }
        false
    }

    /// Check DWARF for CFI flags
    fn check_dwarf_for_cfi(dwarf: &DwarfInfo) -> CfiCheckResult {
        if !dwarf.has_debug_info {
            return CfiCheckResult::NoDwarf;
        }

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

        if !is_clang {
            return CfiCheckResult::NotClang;
        }

        if has_cfi {
            return CfiCheckResult::CfiEnabled;
        }

        if has_lto {
            return CfiCheckResult::LtoWithoutCfi;
        }

        CfiCheckResult::NoCfi
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CfiCheckResult {
    CfiEnabled,
    NoCfi,
    LtoWithoutCfi,
    NotClang,
    NoDwarf,
}

impl Default for PeEnableControlFlowIntegrity {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for PeEnableControlFlowIntegrity {
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
            Ok(d) if d.has_debug_info => d,
            _ => {
                self.log_not_applicable(context, "NotApplicable_NoDwarf", &[&file_name]);
                return;
            }
        };

        // First check for CFI symbols
        if Self::has_cfi_symbols(&dwarf) {
            self.log_pass(context, "Pass_CfiSymbols", &[&file_name]);
            return;
        }

        // Check DWARF producer strings for CFI flags
        match Self::check_dwarf_for_cfi(&dwarf) {
            CfiCheckResult::CfiEnabled => {
                self.log_pass(context, "Pass_DwarfConfirmed", &[&file_name]);
            }
            CfiCheckResult::LtoWithoutCfi => {
                self.log_fail(
                    context,
                    FailureLevel::Warning,
                    "Warning_LtoWithoutCfi",
                    &[&file_name],
                );
            }
            CfiCheckResult::NoCfi => {
                self.log_fail(
                    context,
                    FailureLevel::Warning,
                    "Warning_NoCfi",
                    &[&file_name],
                );
            }
            CfiCheckResult::NotClang => {
                self.log_not_applicable(context, "NotApplicable_NotClang", &[&file_name]);
            }
            CfiCheckResult::NoDwarf => {
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
        let rule = PeEnableControlFlowIntegrity::new();
        assert_eq!(rule.descriptor().id, "AD2036");
        assert_eq!(rule.descriptor().name, "PeEnableControlFlowIntegrity");
        assert_eq!(rule.descriptor().category, RuleCategory::Security);
    }
}
