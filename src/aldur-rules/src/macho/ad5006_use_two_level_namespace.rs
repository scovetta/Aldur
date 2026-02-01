//! AD5006: UseTwoLevelNamespace
//!
//! Checks that the MH_TWOLEVEL flag is set for Mach-O binaries.
//! Two-level namespace binding links symbols to their specific defining library,
//! which provides better security and performance.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::MachOBinary;

use crate::rule_ids::AD5006;

pub struct UseTwoLevelNamespace {
    descriptor: RuleDescriptor,
}

impl UseTwoLevelNamespace {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD5006, "UseTwoLevelNamespace")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "macos-only"])
            .with_short_description("Use two-level namespace for symbol binding.")
            .with_full_description(
                "Two-level namespace binding links symbols to their specific defining library, \
                 rather than searching all loaded libraries in a flat namespace. This prevents \
                 symbol interposition attacks where a malicious library could override symbols \
                 from system libraries. Flat namespace can be forced with '-flat_namespace' \
                 linker flag, which should be avoided.",
            )
            .with_fix_hint("Remove -flat_namespace linker flag")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "Two-level namespace is enabled on '{0}'.",
            )
            .with_message(
                "Warning",
                "'{0}' uses flat namespace instead of two-level namespace. This allows \
                 symbol interposition attacks. Remove the '-flat_namespace' linker flag \
                 to use the more secure two-level namespace.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for UseTwoLevelNamespace {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for UseTwoLevelNamespace {
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

        // Skip object files and core dumps
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

        if macho.has_two_level_namespace() {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(context, FailureLevel::Warning, "Warning", &[&file_name]);
        }
    }
}
