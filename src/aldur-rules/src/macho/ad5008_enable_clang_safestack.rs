//! AD5008: EnableClangSafeStackMachO
//!
//! Checks that Clang-compiled Mach-O binaries use SafeStack.
//! SafeStack provides protection against stack buffer overflows.
//!
//! Note: SafeStack has known compatibility limitations:
//! - Programs using ucontext.h are not supported
//! - Linking DSOs with SafeStack is not supported

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{DwarfInfo, MachOBinary};

use crate::rule_ids::AD5008;

/// Symbols that indicate SafeStack is in use
const SAFESTACK_SYMBOLS: &[&str] = &[
    "__safestack_init",
    "__safestack_unsafe_stack_ptr",
    "__safestack_pointer_address",
];

/// Symbols from ucontext.h that are incompatible with SafeStack
const UCONTEXT_SYMBOLS: &[&str] = &[
    "getcontext",
    "setcontext",
    "makecontext",
    "swapcontext",
];

pub struct EnableClangSafeStackMachO {
    descriptor: RuleDescriptor,
}

impl EnableClangSafeStackMachO {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD5008, "EnableClangSafeStackMachO")
            .with_category(RuleCategory::Security)
            .with_tags(&["hardening", "memory-safety", "macos-only"])
            .with_short_description("Enable Clang SafeStack.")
            .with_full_description(
                "Clang-compiled binaries should use SafeStack to provide strong protection \
                 against stack buffer overflows. SafeStack separates the stack into a safe \
                 stack for return addresses and a separate unsafe stack for buffers. Note: \
                 SafeStack is not compatible with programs using ucontext.h or shared libraries.",
            )
            .with_fix_hint("Compile with -fsanitize=safe-stack (Clang only)")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' enables Clang SafeStack for stack buffer overflow protection.",
            )
            .with_message(
                "Warning_NoSafeStack",
                "'{0}' is compiled with Clang but does not use SafeStack. \
                 Consider adding -fsanitize=safe-stack to enable this protection.",
            )
            .with_message(
                "NotApplicable_NotClang",
                "'{0}' was not compiled with Clang.",
            )
            .with_message(
                "NotApplicable_NoDebugInfo",
                "'{0}' does not contain debug information to determine compiler.",
            )
            .with_message(
                "NotApplicable_UsesUcontext",
                "'{0}' uses ucontext.h functions which are not compatible with SafeStack.",
            )
            .with_message(
                "NotApplicable_SharedLibrary",
                "'{0}' is a shared library. SafeStack does not support DSOs.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}': {2}.",
            );

        Self { descriptor }
    }
}

impl Default for EnableClangSafeStackMachO {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableClangSafeStackMachO {
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

        // Check for SafeStack symbols first - if present, it passes regardless
        if macho.has_any_symbol(SAFESTACK_SYMBOLS) {
            self.log_pass(context, "Pass", &[&file_name]);
            return;
        }

        // Check for compatibility issues before warning about missing SafeStack

        // 1. Check if this is a shared library (SafeStack doesn't support DSOs)
        if macho.is_shared_library() {
            self.log_not_applicable(context, "NotApplicable_SharedLibrary", &[&file_name]);
            return;
        }

        // 2. Check for ucontext.h functions which are incompatible with SafeStack
        if macho.has_any_symbol(UCONTEXT_SYMBOLS) {
            self.log_not_applicable(context, "NotApplicable_UsesUcontext", &[&file_name]);
            return;
        }

        // 3. Check compiler information from DWARF
        let dwarf_info = match DwarfInfo::parse(macho.data()) {
            Ok(info) => info,
            Err(_) => {
                self.log_not_applicable(context, "NotApplicable_NoDebugInfo", &[&file_name]);
                return;
            }
        };

        if dwarf_info.compilation_units.is_empty() {
            self.log_not_applicable(context, "NotApplicable_NoDebugInfo", &[&file_name]);
            return;
        }

        // Check if compiled with Clang
        let has_clang = dwarf_info.compilation_units.iter().any(|cu| {
            cu.compiler_info
                .name
                .as_ref()
                .map(|n| n.to_lowercase().contains("clang") || n.to_lowercase().contains("llvm"))
                .unwrap_or(false)
        });

        if !has_clang {
            self.log_not_applicable(context, "NotApplicable_NotClang", &[&file_name]);
            return;
        }

        // Clang binary without SafeStack
        self.log_fail(context, FailureLevel::Warning, "Warning_NoSafeStack", &[&file_name]);
    }
}
