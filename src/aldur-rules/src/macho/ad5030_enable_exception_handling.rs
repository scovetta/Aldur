//! AD5030: EnableExceptionHandlingMachO
//!
//! Checks that Mach-O binaries have exception handling frames which are
//! recommended for proper stack unwinding and thread safety.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::MachOBinary;

use crate::rule_ids::AD5030;

pub struct EnableExceptionHandlingMachO {
    descriptor: RuleDescriptor,
}

impl EnableExceptionHandlingMachO {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD5030, "EnableExceptionHandlingMachO")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "macos-only"])
            .with_short_description(
                "Binaries should include exception handling frames for proper stack unwinding.",
            )
            .with_full_description(
                "The -fexceptions compiler option generates frame unwind information for \
                 all functions. This allows proper exception handling and stack unwinding, \
                 which is important for C++ code and for debugging. Without exception handling \
                 frames, stack traces may be incomplete and cleanup handlers may not run. \
                 On macOS, the __unwind_info section contains compact unwind information.",
            )
            .with_fix_hint("Compile with -fexceptions (enabled by default)")
            .with_default_level(FailureLevel::Note)
            .with_message(
                "Pass",
                "'{0}' contains exception handling frames (__unwind_info or __eh_frame section).",
            )
            .with_message(
                "Note",
                "'{0}' does not contain exception handling frames. Consider compiling with \
                 '-fexceptions' to enable proper stack unwinding and exception handling.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }

    /// Check for exception handling sections
    fn has_exception_handling(macho: &MachOBinary) -> bool {
        // Check segments for unwind info
        // Mach-O uses compact unwind info stored in __TEXT segment
        for seg in &macho.segments {
            if seg.name == "__TEXT" {
                // The presence of __TEXT segment with sections like __unwind_info
                // indicates exception handling. We check via symbol presence.
            }
        }

        // Check for unwind-related symbols
        let unwind_symbols = &[
            "__unwind_info",
            "__eh_frame",
            "_Unwind_Resume",
            "_Unwind_RaiseException",
            "___gxx_personality_v0",
            "__gcc_personality_v0",
        ];

        macho.has_any_symbol(unwind_symbols)
    }
}

impl Default for EnableExceptionHandlingMachO {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableExceptionHandlingMachO {
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

        if Self::has_exception_handling(macho) {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(context, FailureLevel::Note, "Note", &[&file_name]);
        }
    }
}
