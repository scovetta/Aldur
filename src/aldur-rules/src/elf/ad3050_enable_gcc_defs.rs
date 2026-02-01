//! AD3050: EnableGccDefs
//!
//! Check that ELF binaries are built with -Wl,-z,defs to catch underlinking issues.
//! This is especially important on RHEL-based distributions.
//!
//! Note: This check verifies that no undefined symbols exist in the dynamic symbol
//! table, which is the effect of using -Wl,-z,defs. The presence of undefined symbols
//! indicates potential underlinking which can cause runtime failures and security issues.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::ElfBinary;
use goblin::elf::{sym::STB_WEAK, Elf};

use crate::rule_ids::AD3050;

pub struct EnableGccDefs {
    descriptor: RuleDescriptor,
}

impl EnableGccDefs {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD3050, "EnableGccDefs")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "linux-only", "rhel-annocheck"])
            .with_short_description(
                "ELF binaries should be built with -Wl,-z,defs to catch underlinking.",
            )
            .with_full_description(
                "ELF shared libraries and executables should be built with the '-Wl,-z,defs' \
                 linker flag to catch underlinking issues at link time rather than runtime. \
                 Underlinking occurs when a shared library depends on symbols from another \
                 library but doesn't explicitly link against it. This can cause runtime \
                 failures and make it harder to understand the binary's true dependencies. \
                 The -z defs flag causes the linker to fail if there are unresolved symbol \
                 references when building a shared object.",
            )
            .with_fix_hint("Link with -Wl,-z,defs")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' has no undefined dynamic symbols, indicating proper linking.",
            )
            .with_message(
                "Warning_UndefinedSymbols",
                "'{0}' has {1} undefined dynamic symbol(s), which may indicate underlinking. \
                 Consider building with '-Wl,-z,defs' to catch missing library dependencies \
                 at link time. Undefined symbols: {2}",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            )
            .with_message(
                "NotApplicable_NotSharedLibrary",
                "'{0}' was not evaluated for check '{1}' as it is not a shared library.",
            );

        Self { descriptor }
    }

    /// Get undefined symbols from the ELF dynamic symbol table
    fn get_undefined_dynamic_symbols(data: &[u8]) -> Vec<String> {
        let mut undefined = Vec::new();

        if let Ok(elf) = Elf::parse(data) {
            for sym in &elf.dynsyms {
                // Check if symbol is undefined (section index is SHN_UNDEF = 0)
                // and has a name and is not a weak symbol
                if sym.st_shndx == 0 && sym.st_name != 0 {
                    // Skip weak symbols as they're allowed to be undefined
                    let bind = sym.st_bind();
                    if bind != STB_WEAK {
                        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                            // Skip common special symbols
                            if !name.is_empty()
                                && !name.starts_with("__gmon")
                                && !name.starts_with("_ITM")
                                && !name.starts_with("__cxa_")
                                && name != "__libc_start_main"
                                && name != "__stack_chk_fail"
                            {
                                undefined.push(name.to_string());
                            }
                        }
                    }
                }
            }
        }

        undefined
    }
}

impl Default for EnableGccDefs {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableGccDefs {
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

        // This check is most relevant for shared libraries
        if !elf.is_shared_library() {
            self.log_not_applicable(
                context,
                "NotApplicable_NotSharedLibrary",
                &[&file_name, self.name()],
            );
            return;
        }

        let data = elf.data();
        let undefined_symbols = Self::get_undefined_dynamic_symbols(data);

        if undefined_symbols.is_empty() {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            // Limit the number of symbols shown to avoid overly long messages
            let display_count = undefined_symbols.len().min(10);
            let symbol_list = if undefined_symbols.len() > display_count {
                format!(
                    "{} (and {} more)",
                    undefined_symbols[..display_count].join(", "),
                    undefined_symbols.len() - display_count
                )
            } else {
                undefined_symbols.join(", ")
            };

            self.log_fail(
                context,
                FailureLevel::Warning,
                "Warning_UndefinedSymbols",
                &[
                    &file_name,
                    &undefined_symbols.len().to_string(),
                    &symbol_list,
                ],
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_descriptor() {
        let rule = EnableGccDefs::new();
        assert_eq!(rule.descriptor().id, AD3050);
        assert_eq!(rule.descriptor().name, "EnableGccDefs");
    }
}
