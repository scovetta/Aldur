//! AD3025: EnableExceptionHandling
//!
//! Checks that binaries have exception handling frames (.eh_frame) which is
//! recommended for multi-threaded C code using pthreads to enable proper
//! thread cancellation handling without exposing function pointers on the stack.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::ElfBinary;

use crate::rule_ids::AD3025;

pub struct EnableExceptionHandling {
    descriptor: RuleDescriptor,
}

impl EnableExceptionHandling {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD3025, "EnableExceptionHandling")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "memory-safety", "openssf"])
            .with_short_description("Binaries should include exception handling frames for thread safety.")
            .with_full_description(
                "The -fexceptions compiler option generates frame unwind information for \
                 all functions. This allows glibc's implementation of POSIX thread \
                 cancellation to use proper stack unwinding instead of setjmp/longjmp. \
                 Without exception handling frames, glibc's thread cancellation handlers \
                 may spill an unprotected function pointer onto the stack, which can \
                 simplify exploitation of stack-based buffer overflows. This is \
                 recommended by the OpenSSF Compiler Hardening Guide for C and C++.",
            )
            .with_fix_hint("Compile with -fexceptions")
            .with_default_level(FailureLevel::Note)
            .with_message(
                "Pass",
                "'{0}' contains exception handling frames (.eh_frame or .eh_frame_hdr section).",
            )
            .with_message(
                "Note",
                "'{0}' does not contain exception handling frames. For multi-threaded code, \
                 consider compiling with '-fexceptions' to enable proper thread cancellation \
                 handling and reduce attack surface.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for EnableExceptionHandling {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableExceptionHandling {
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

        if elf.has_exception_handling {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            // Note level - important for multi-threaded code but not a hard requirement
            self.log_fail(
                context,
                FailureLevel::Note,
                "Note",
                &[&file_name],
            );
        }
    }
}
