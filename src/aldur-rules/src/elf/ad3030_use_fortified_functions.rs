//! AD3030: UseGccCheckedFunctions (Fortified Functions)
//!
//! Checks that FORTIFY_SOURCE is enabled (_FORTIFY_SOURCE=3 recommended).
//! This replaces dangerous functions like strcpy with bounds-checked versions.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::ElfBinary;

use crate::rule_ids::AD3030;

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
    "__gets_chk",
    "__fgets_chk",
    "__read_chk",
    "__pread_chk",
    "__realpath_chk",
    "__wctomb_chk",
    "__mbstowcs_chk",
    "__wcstombs_chk",
    "__longjmp_chk",
    "__fdelt_chk",
];

pub struct UseGccCheckedFunctions {
    descriptor: RuleDescriptor,
}

impl UseGccCheckedFunctions {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD3030, "UseGccCheckedFunctions")
            .with_category(RuleCategory::Security)
            .with_tags(&[
                "recommended",
                "memory-safety",
                "android-cdd",
                "rhel-annocheck",
                "openssf",
            ])
            .with_short_description("Use GCC/glibc fortified functions (FORTIFY_SOURCE).")
            .with_full_description(
                "FORTIFY_SOURCE replaces dangerous libc functions like strcpy, sprintf, memcpy \
                 with bounds-checked versions that can detect buffer overflows at runtime. \
                 Compile with '-D_FORTIFY_SOURCE=3' (GCC 12+/Clang 12+) or '-D_FORTIFY_SOURCE=2' \
                 and '-O2' or higher optimization level to enable this protection. Level 3 \
                 provides additional protection for dynamically-allocated buffers.",
            )
            .with_fix_hint("Compile with -D_FORTIFY_SOURCE=3 -O2 (or =2 for older compilers)")
            .with_default_level(FailureLevel::Warning)
            .with_message("Pass", "Fortified functions are used in '{0}'.")
            .with_message(
                "Warning",
                "No fortified functions found in '{0}'. Consider compiling with \
                 '-D_FORTIFY_SOURCE=3 -O2' (GCC 12+/Clang 12+) or '-D_FORTIFY_SOURCE=2 -O2' \
                 to enable bounds-checked libc functions.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            )
            .with_message(
                "NotApplicable_NoLibcCalls",
                "'{0}' does not appear to use any libc functions that can be fortified.",
            )
            .with_message(
                "NotApplicable_RustBinary",
                "'{0}' is a Rust binary. FORTIFY_SOURCE is not applicable because Rust \
                 has built-in memory safety and bounds checking.",
            );

        Self { descriptor }
    }
}

impl Default for UseGccCheckedFunctions {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for UseGccCheckedFunctions {
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

        // FORTIFY_SOURCE is a C/C++ libc feature and doesn't apply to Rust binaries
        // Rust has built-in bounds checking and doesn't use vulnerable libc functions
        if elf.is_rust_binary {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Rust binary - FORTIFY_SOURCE not applicable".to_string()),
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

        if elf.has_any_symbol(FORTIFIED_FUNCTIONS) {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(context, FailureLevel::Warning, "Warning", &[&file_name]);
        }
    }
}
