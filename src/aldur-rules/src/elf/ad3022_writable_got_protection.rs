//! AD3022: WritableGotProtection
//!
//! Checks that the Global Offset Table (GOT) is not writable without RELRO protection.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::ElfBinary;

use crate::rule_ids::AD3022;

pub struct WritableGotProtection {
    descriptor: RuleDescriptor,
}

impl WritableGotProtection {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD3022, "WritableGotProtection")
            .with_category(RuleCategory::Security)
            .with_tags(&["critical", "memory-safety", "linux-only", "android-cdd", "rhel-annocheck", "openssf"])
            .with_short_description("Protect the Global Offset Table (GOT) from writes.")
            .with_full_description(
                "The Global Offset Table (GOT) contains addresses of global variables and \
                 functions. If the GOT is writable at runtime without RELRO protection, \
                 attackers can overwrite these addresses to redirect program execution. \
                 Enable full RELRO by linking with '-Wl,-z,relro,-z,now' to make the GOT \
                 read-only after relocation.",
            )
            .with_fix_hint("Link with -Wl,-z,relro,-z,now for full RELRO")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' has full RELRO protection, making the GOT read-only.",
            )
            .with_message(
                "Warning_PartialRelro",
                "'{0}' has partial RELRO but the GOT may still be writable. Use full RELRO \
                 by linking with '-Wl,-z,relro,-z,now'.",
            )
            .with_message(
                "Error_NoRelro",
                "'{0}' has no RELRO protection. The GOT is writable and can be exploited. \
                 Link with '-Wl,-z,relro,-z,now' to enable full RELRO.",
            )
            .with_message(
                "NotApplicable_StaticBinary",
                "'{0}' appears to be a static binary without a GOT.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}': {2}.",
            );

        Self { descriptor }
    }

    fn check_got_protection(elf: &ElfBinary) -> GotProtectionLevel {
        // Full RELRO means GOT is completely read-only
        if elf.has_full_relro() {
            return GotProtectionLevel::FullRelro;
        }

        // Partial RELRO means some protection but GOT.PLT still writable
        if elf.has_relro {
            return GotProtectionLevel::PartialRelro;
        }

        // Check if there's even a dynamic section (static binaries don't have GOT)
        // We can infer this from the presence of certain segments
        let has_dynamic = elf.segments.iter().any(|s| {
            s.p_type == aldur_parsers::elf::ph_type::PT_DYNAMIC
        });

        if !has_dynamic {
            return GotProtectionLevel::StaticBinary;
        }

        GotProtectionLevel::NoRelro
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum GotProtectionLevel {
    FullRelro,
    PartialRelro,
    NoRelro,
    StaticBinary,
}

impl Default for WritableGotProtection {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for WritableGotProtection {
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

        match elf.elf_type {
            ElfType::Core | ElfType::None | ElfType::Relocatable => {
                return (
                    AnalysisApplicability::NotApplicableToSpecifiedTarget,
                    Some("ELF is core, none, or relocatable".to_string()),
                );
            }
            _ => {}
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

        match Self::check_got_protection(elf) {
            GotProtectionLevel::FullRelro => {
                self.log_pass(context, "Pass", &[&file_name]);
            }
            GotProtectionLevel::PartialRelro => {
                self.log_fail(
                    context,
                    FailureLevel::Warning,
                    "Warning_PartialRelro",
                    &[&file_name],
                );
            }
            GotProtectionLevel::NoRelro => {
                self.log_fail(
                    context,
                    FailureLevel::Error,
                    "Error_NoRelro",
                    &[&file_name],
                );
            }
            GotProtectionLevel::StaticBinary => {
                self.log_not_applicable(
                    context,
                    "NotApplicable_StaticBinary",
                    &[&file_name],
                );
            }
        }
    }
}
