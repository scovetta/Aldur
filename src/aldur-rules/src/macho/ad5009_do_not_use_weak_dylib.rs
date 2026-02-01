//! AD5009: DoNotUseWeakDylib
//!
//! Checks that Mach-O binaries do not use LC_LOAD_WEAK_DYLIB load commands.
//! Weak dylibs are optional at load time and could be replaced by an attacker,
//! leading to "dylib hijacking" attacks.
//!
//! This is primarily a concern on macOS rather than iOS.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::MachOBinary;

use crate::rule_ids::AD5009;

pub struct DoNotUseWeakDylib {
    descriptor: RuleDescriptor,
}

impl DoNotUseWeakDylib {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD5009, "DoNotUseWeakDylib")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "macos-only"])
            .with_short_description("Do not use weak dylib loading (LC_LOAD_WEAK_DYLIB).")
            .with_full_description(
                "Weak dylibs (LC_LOAD_WEAK_DYLIB) are optional during load time. If a weak \
                 dylib is not found, the loader continues anyway. This can be exploited by \
                 attackers who place a malicious library at the expected location. Avoid \
                 using the '-weak_library' or '-weak-l' linker flags. Use strong dylib \
                 references or bundle the required libraries with your application.",
            )
            .with_fix_hint("Remove weak_import or bundle required libraries")
            .with_default_level(FailureLevel::Warning)
            .with_message("Pass", "'{0}' does not use weak dylib loading.")
            .with_message(
                "Warning",
                "'{0}' uses weak dylib loading: {1}. Weak dylibs can be hijacked by \
                 attackers. Consider using strong library references instead.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for DoNotUseWeakDylib {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DoNotUseWeakDylib {
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

        if !macho.has_weak_dylib {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            let dylibs = macho.weak_dylibs.join(", ");
            self.log_fail(
                context,
                FailureLevel::Warning,
                "Warning",
                &[&file_name, &dylibs],
            );
        }
    }
}
