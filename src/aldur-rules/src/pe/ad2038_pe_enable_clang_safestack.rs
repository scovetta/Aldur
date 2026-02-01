//! AD2038: PeEnableClangSafeStack
//!
//! Checks for Clang SafeStack in PE binaries with DWARF debug info.
//! SafeStack provides strong protection against stack buffer overflows.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, Binary, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{DwarfInfo, PeBinary};

use crate::rule_ids::AD2038;

/// Symbols that indicate SafeStack is in use
const SAFESTACK_SYMBOLS: &[&str] = &[
    "__safestack_init",
    "__safestack_unsafe_stack_ptr",
    "__safestack_pointer_address",
];

pub struct PeEnableClangSafeStack {
    descriptor: RuleDescriptor,
}

impl PeEnableClangSafeStack {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2038, "PeEnableClangSafeStack")
            .with_category(RuleCategory::Security)
            .with_tags(&["hardening", "memory-safety", "windows-only"])
            .with_short_description("Enable Clang SafeStack for PE binaries built with Clang.")
            .with_full_description(
                "PE binaries built with Clang should consider using SafeStack to provide \
                 strong protection against stack buffer overflows. SafeStack separates the \
                 stack into a safe stack for return addresses and a separate unsafe stack \
                 for buffers, making it much harder to exploit stack-based vulnerabilities. \
                 Enable with '-fsanitize=safe-stack'. Note: SafeStack is not compatible with \
                 programs using ucontext.h, shared libraries, or multi-compiler binaries.",
            )
            .with_fix_hint("Compile with -fsanitize=safe-stack (Clang only)")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' enables Clang SafeStack for stack buffer overflow protection.",
            )
            .with_message(
                "Pass_SafeStackSymbol",
                "'{0}' has SafeStack enabled (__safestack_init symbol found).",
            )
            .with_message(
                "Pass_DwarfConfirmed",
                "'{0}' has SafeStack enabled (confirmed via DWARF debug info).",
            )
            .with_message(
                "Warning_NoSafeStack",
                "'{0}' is compiled with Clang but does not use SafeStack. \
                 Consider adding '-fsanitize=safe-stack' to enable this protection.",
            )
            .with_message(
                "NotApplicable_NoDwarf",
                "'{0}' does not contain DWARF debug information.",
            )
            .with_message(
                "NotApplicable_NotClang",
                "'{0}' was not compiled with Clang. SafeStack is a Clang-specific feature.",
            )
            .with_message(
                "NotApplicable_MultiCompiler",
                "'{0}' was compiled with multiple compilers. SafeStack requires all \
                 code to be compiled with Clang -fsanitize=safe-stack.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}': {2}.",
            );

        Self { descriptor }
    }

    /// Check for SafeStack symbols in DWARF info
    fn has_safestack_symbols(dwarf: &DwarfInfo) -> bool {
        for cu in &dwarf.compilation_units {
            let producer = &cu.compiler_info.producer;
            for symbol in SAFESTACK_SYMBOLS {
                if producer.contains(symbol) {
                    return true;
                }
            }
        }
        false
    }

    /// Check DWARF for SafeStack and compiler info
    fn check_dwarf_for_safestack(dwarf: &DwarfInfo) -> SafeStackResult {
        if !dwarf.has_debug_info || dwarf.compilation_units.is_empty() {
            return SafeStackResult::NoDwarf;
        }

        let mut has_clang = false;
        let mut has_other_compiler = false;
        let mut has_safestack = false;

        for cu in &dwarf.compilation_units {
            // Check compiler type
            if let Some(ref name) = cu.compiler_info.name {
                let name_lower = name.to_lowercase();
                if name_lower.contains("clang") || name_lower.contains("llvm") {
                    has_clang = true;
                } else if name_lower.contains("gcc")
                    || name_lower.contains("gnu c")
                    || name_lower.contains("rustc")
                    || name_lower.contains("icc")
                    || name_lower.contains("intel")
                {
                    has_other_compiler = true;
                }
            }

            // Also check parsed_info for compiler type
            if cu.parsed_info.compiler_type == aldur_parsers::dwarf::CompilerType::Clang {
                has_clang = true;
            }

            // Check for SafeStack flags in producer or command line
            let producer = &cu.compiler_info.producer;
            if producer.contains("-fsanitize=safe-stack")
                || producer.contains("sanitize=safe-stack")
            {
                has_safestack = true;
            }

            // Check individual flags
            for flag in &cu.parsed_info.flags {
                if flag.contains("sanitize=safe-stack") || flag == "-fsanitize=safe-stack" {
                    has_safestack = true;
                }
            }
        }

        // Not compiled with Clang at all
        if !has_clang {
            return SafeStackResult::NotClang;
        }

        // Multi-compiler binary - SafeStack requires all code to be compiled with SafeStack
        if has_clang && has_other_compiler {
            return SafeStackResult::MultiCompiler;
        }

        if has_safestack {
            return SafeStackResult::SafeStackEnabled;
        }

        SafeStackResult::NoSafeStack
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SafeStackResult {
    SafeStackEnabled,
    NoSafeStack,
    NotClang,
    MultiCompiler,
    NoDwarf,
}

impl Default for PeEnableClangSafeStack {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for PeEnableClangSafeStack {
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

        // First check for SafeStack symbols
        if Self::has_safestack_symbols(&dwarf) {
            self.log_pass(context, "Pass_SafeStackSymbol", &[&file_name]);
            return;
        }

        // Check DWARF producer strings for SafeStack flags
        match Self::check_dwarf_for_safestack(&dwarf) {
            SafeStackResult::SafeStackEnabled => {
                self.log_pass(context, "Pass_DwarfConfirmed", &[&file_name]);
            }
            SafeStackResult::NoSafeStack => {
                self.log_fail(
                    context,
                    FailureLevel::Warning,
                    "Warning_NoSafeStack",
                    &[&file_name],
                );
            }
            SafeStackResult::NotClang => {
                self.log_not_applicable(context, "NotApplicable_NotClang", &[&file_name]);
            }
            SafeStackResult::MultiCompiler => {
                self.log_not_applicable(context, "NotApplicable_MultiCompiler", &[&file_name]);
            }
            SafeStackResult::NoDwarf => {
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
        let rule = PeEnableClangSafeStack::new();
        assert_eq!(rule.descriptor().id, "AD2038");
        assert_eq!(rule.descriptor().name, "PeEnableClangSafeStack");
        assert_eq!(rule.descriptor().category, RuleCategory::Security);
    }
}
