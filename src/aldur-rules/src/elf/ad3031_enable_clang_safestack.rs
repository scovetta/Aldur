//! AD3031: EnableClangSafeStack
//!
//! Ensures Clang-compiled ELF binaries enable SafeStack.
//! SafeStack provides protection against stack buffer overflows.
//!
//! Note: SafeStack has known compatibility limitations:
//! - Programs using ucontext.h (getcontext, setcontext, makecontext, swapcontext) are not supported
//! - Linking DSOs with SafeStack is not supported
//! - Multi-compiler binaries (mixed GCC/Clang) may not be compatible
//! - Signal handlers using sigaltstack() may not work correctly
//!
//! See: https://releases.llvm.org/3.8.0/tools/clang/docs/SafeStack.html

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{DwarfInfo, ElfBinary};

use crate::rule_ids::AD3031;

/// Symbols that indicate SafeStack is in use
const SAFESTACK_SYMBOLS: &[&str] = &[
    "__safestack_init",
    "__safestack_unsafe_stack_ptr",
    "__safestack_pointer_address",
];

/// Symbols from ucontext.h that are incompatible with SafeStack
const UCONTEXT_SYMBOLS: &[&str] = &["getcontext", "setcontext", "makecontext", "swapcontext"];

pub struct EnableClangSafeStack {
    descriptor: RuleDescriptor,
}

impl EnableClangSafeStack {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD3031, "EnableClangSafeStack")
            .with_category(RuleCategory::Security)
            .with_tags(&["hardening", "memory-safety", "linux-only"])
            .with_short_description("Enable Clang SafeStack.")
            .with_full_description(
                "Clang-compiled binaries should use SafeStack to provide strong protection \
                 against stack buffer overflows. SafeStack separates the stack into a safe \
                 stack for return addresses and a separate unsafe stack for buffers, making \
                 it much harder to exploit stack-based vulnerabilities. Note: SafeStack is \
                 not compatible with programs using ucontext.h, shared libraries, or \
                 multi-compiler binaries.",
            )
            .with_fix_hint("Compile with -fsanitize=safe-stack (Clang only)")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' enables Clang SafeStack for stack buffer overflow protection.",
            )
            .with_message(
                "Warning_NoSafeStack",
                "'{0}' is compiled exclusively with Clang but does not use SafeStack. \
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
                "NotApplicable_MultiCompiler",
                "'{0}' was compiled with multiple compilers. SafeStack requires all \
                 code to be compiled with Clang -fsanitize=safe-stack.",
            )
            .with_message(
                "NotApplicable_UsesUcontext",
                "'{0}' uses ucontext.h functions (getcontext/setcontext/makecontext/swapcontext) \
                 which are not compatible with SafeStack.",
            )
            .with_message(
                "NotApplicable_SharedLibrary",
                "'{0}' is a shared library. SafeStack does not support DSOs.",
            )
            .with_message(
                "NotApplicable_RustBinary",
                "'{0}' is a Rust binary. SafeStack is a Clang-specific feature not available for Rust.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}': {2}.",
            );

        Self { descriptor }
    }
}

impl Default for EnableClangSafeStack {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableClangSafeStack {
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

        // Rust binaries cannot use SafeStack - it's Clang-specific
        if elf.is_rust_binary {
            self.log_not_applicable(context, "NotApplicable_RustBinary", &[&file_name]);
            return;
        }

        // Check for SafeStack symbols first - if present, it passes regardless
        let has_safestack = elf.has_any_symbol(SAFESTACK_SYMBOLS);
        if has_safestack {
            self.log_pass(context, "Pass", &[&file_name]);
            return;
        }

        // Check for compatibility issues before warning about missing SafeStack

        // 1. Check if this is a shared library (SafeStack doesn't support DSOs)
        if elf.is_shared_library() {
            self.log_not_applicable(context, "NotApplicable_SharedLibrary", &[&file_name]);
            return;
        }

        // 2. Check for ucontext.h functions which are incompatible with SafeStack
        if elf.has_any_symbol(UCONTEXT_SYMBOLS) {
            self.log_not_applicable(context, "NotApplicable_UsesUcontext", &[&file_name]);
            return;
        }

        // 3. Check compiler information from DWARF
        let dwarf_info = match DwarfInfo::parse(elf.data()) {
            Ok(info) => info,
            Err(_) => {
                // No DWARF info - can't determine compiler, mark as not applicable
                self.log_not_applicable(context, "NotApplicable_NoDebugInfo", &[&file_name]);
                return;
            }
        };

        if dwarf_info.compilation_units.is_empty() {
            self.log_not_applicable(context, "NotApplicable_NoDebugInfo", &[&file_name]);
            return;
        }

        // Count compilers used
        let mut has_clang = false;
        let mut has_other_compiler = false;

        for cu in &dwarf_info.compilation_units {
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
        }

        // 4. Not compiled with Clang at all
        if !has_clang {
            self.log_not_applicable(context, "NotApplicable_NotClang", &[&file_name]);
            return;
        }

        // 5. Multi-compiler binary (Clang + GCC/other) - SafeStack requires all code
        //    to be compiled with SafeStack, so mixed binaries can't use it
        if has_clang && has_other_compiler {
            self.log_not_applicable(context, "NotApplicable_MultiCompiler", &[&file_name]);
            return;
        }

        // Binary is exclusively Clang-compiled and has no compatibility issues,
        // but SafeStack is not enabled - this is a valid warning
        self.log_fail(
            context,
            FailureLevel::Warning,
            "Warning_NoSafeStack",
            &[&file_name],
        );
    }
}
