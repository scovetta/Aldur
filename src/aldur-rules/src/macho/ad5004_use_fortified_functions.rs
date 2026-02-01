//! AD5004: UseFortifiedFunctionsMachO
//!
//! Checks that FORTIFY_SOURCE is enabled (_FORTIFY_SOURCE=2).
//! This replaces dangerous functions like strcpy with bounds-checked versions.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::MachOBinary;

use crate::rule_ids::AD5004;

/// Common fortified functions that indicate FORTIFY_SOURCE is enabled
const FORTIFIED_FUNCTIONS: &[&str] = &[
    "__memcpy_chk",
    "__memmove_chk",
    "__memset_chk",
    "__strcpy_chk",
    "__strncpy_chk",
    "__strcat_chk",
    "__strncat_chk",
    "__sprintf_chk",
    "__snprintf_chk",
    "__vsprintf_chk",
    "__vsnprintf_chk",
    "__fprintf_chk",
    "__printf_chk",
    "__vfprintf_chk",
    "__vprintf_chk",
];

pub struct UseFortifiedFunctionsMachO {
    descriptor: RuleDescriptor,
}

impl UseFortifiedFunctionsMachO {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD5004, "UseFortifiedFunctionsMachO")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "memory-safety", "macos-only", "openssf"])
            .with_short_description("Use fortified functions (FORTIFY_SOURCE).")
            .with_full_description(
                "FORTIFY_SOURCE replaces dangerous libc functions like strcpy, sprintf, memcpy \
                 with bounds-checked versions that can detect buffer overflows at runtime. \
                 Compile with '-D_FORTIFY_SOURCE=2' and '-O2' or higher optimization level \
                 to enable this protection.",
            )
            .with_fix_hint("Compile with -D_FORTIFY_SOURCE=2 -O2")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "Fortified functions are used in '{0}'.",
            )
            .with_message(
                "Warning",
                "No fortified functions found in '{0}'. Consider compiling with \
                 '-D_FORTIFY_SOURCE=2 -O2' to enable bounds-checked libc functions.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for UseFortifiedFunctionsMachO {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for UseFortifiedFunctionsMachO {
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

        if macho.has_any_symbol(FORTIFIED_FUNCTIONS) {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(context, FailureLevel::Warning, "Warning", &[&file_name]);
        }
    }
}
