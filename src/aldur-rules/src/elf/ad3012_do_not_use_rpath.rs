//! AD3012: DoNotUseRpath
//!
//! Checks that binaries do not use DT_RPATH, which is deprecated and
//! can be a security risk due to library injection attacks.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::ElfBinary;

use crate::rule_ids::AD3012;

pub struct DoNotUseRpath {
    descriptor: RuleDescriptor,
}

impl DoNotUseRpath {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD3012, "DoNotUseRpath")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "linux-only"])
            .with_short_description("Do not use DT_RPATH for library search paths.")
            .with_full_description(
                "DT_RPATH is deprecated in favor of DT_RUNPATH and can be a security risk. \
                 RPATH takes precedence over LD_LIBRARY_PATH and can be used for library \
                 injection attacks if it contains writable directories. Use RUNPATH instead \
                 by linking with '--enable-new-dtags', or avoid runtime paths entirely.",
            )
            .with_fix_hint("Link with -Wl,--enable-new-dtags or remove -rpath")
            .with_default_level(FailureLevel::Warning)
            .with_message("Pass", "'{0}' does not use DT_RPATH.")
            .with_message(
                "Warning",
                "'{0}' uses deprecated DT_RPATH: '{1}'. Consider using RUNPATH instead \
                 by linking with '--enable-new-dtags'.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for DoNotUseRpath {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DoNotUseRpath {
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

        if let Some(ref rpath) = elf.rpath {
            self.log_fail(
                context,
                FailureLevel::Warning,
                "Warning",
                &[&file_name, rpath],
            );
        } else {
            self.log_pass(context, "Pass", &[&file_name]);
        }
    }
}
