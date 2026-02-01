//! AD3024: RestrictDlopen
//!
//! Checks that shared objects are marked with DF_1_NOOPEN flag from -Wl,-z,nodlopen
//! to restrict dlopen() calls and reduce attack surface.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::ElfBinary;

use crate::rule_ids::AD3024;

/// DF_1_NOOPEN flag value (from ELF specification)
/// This flag marks the object as not available to dlopen()
const DF_1_NOOPEN: u64 = 0x40;

pub struct RestrictDlopen {
    descriptor: RuleDescriptor,
}

impl RestrictDlopen {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD3024, "RestrictDlopen")
            .with_category(RuleCategory::Security)
            .with_tags(&["hardening", "openssf"])
            .with_short_description("Shared objects should restrict dlopen() access where possible.")
            .with_full_description(
                "The -Wl,-z,nodlopen linker option marks shared objects as not available to \
                 dlopen(3) calls. This can help reduce an attacker's ability to load and \
                 manipulate shared objects. Loading new objects or duplicating an already \
                 existing shared object in a process can constitute part of an attack chain \
                 in runtime exploitation. This is recommended by the OpenSSF Compiler \
                 Hardening Guide for C and C++.",
            )
            .with_fix_hint("Link with -Wl,-z,nodlopen")
            .with_default_level(FailureLevel::Note)
            .with_message(
                "Pass",
                "'{0}' is marked with DF_1_NOOPEN flag, restricting dlopen() access.",
            )
            .with_message(
                "Note",
                "'{0}' is not marked with DF_1_NOOPEN flag. Consider linking with \
                 '-Wl,-z,nodlopen' to restrict dlopen() access and reduce attack surface.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for RestrictDlopen {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for RestrictDlopen {
    fn descriptor(&self) -> &RuleDescriptor {
        &self.descriptor
    }

    fn can_analyze(
        &self,
        context: &AnalysisContext,
    ) -> (AnalysisApplicability, Option<String>) {
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

        use aldur_parsers::elf::ElfType;

        // Only applicable to shared objects (libraries and PIE executables)
        match elf.elf_type {
            ElfType::SharedObject => {
                // This is most relevant for shared libraries
                (AnalysisApplicability::ApplicableToSpecifiedTarget, None)
            }
            _ => {
                // Regular executables don't need this flag
                (
                    AnalysisApplicability::NotApplicableToSpecifiedTarget,
                    Some("Not a shared object".to_string()),
                )
            }
        }
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

        // Check for DF_1_NOOPEN flag in DT_FLAGS_1
        let has_noopen = (elf.dt_flags_1 & DF_1_NOOPEN) != 0;

        if has_noopen {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            // This is a Note level - informational, not a hard requirement
            self.log_fail(
                context,
                FailureLevel::Note,
                "Note",
                &[&file_name],
            );
        }
    }
}
