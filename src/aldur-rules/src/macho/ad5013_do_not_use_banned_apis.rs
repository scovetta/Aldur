//! AD5013: DoNotUseBannedApisMachO
//!
//! Checks that Mach-O binaries do not use known dangerous/banned API functions.
//! These functions are prone to buffer overflows and other security vulnerabilities.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::MachOBinary;

use crate::rule_ids::AD5013;

/// Banned API functions that are known security risks (C17/C23 standards).
///
/// Note: We focus on functions that are almost always dangerous or have
/// safer alternatives. Functions like memcpy/memmove/memset are used by
/// many runtimes and compilers internally, so we don't flag those.
const BANNED_APIS: &[&str] = &[
    // === String operations without bounds checking ===
    "strcpy",
    "strcat",
    "strncpy", // May not null-terminate
    "strncat", // Complex size calculations
    "wcscpy",
    "wcscat",
    "wcsncpy",
    "wcsncat",
    // === Format string functions (buffer overflow + format string attacks) ===
    "sprintf",
    "vsprintf",
    "swprintf",
    "vswprintf",
    // === Dangerous scanf variants (no bounds on %s) ===
    "scanf",
    "sscanf",
    "fscanf",
    "vscanf",
    "vsscanf",
    "vfscanf",
    "wscanf",
    "swscanf",
    "fwscanf",
    "vwscanf",
    "vswscanf",
    "vfwscanf",
    // === Input functions (buffer overflow) ===
    "gets", // REMOVED from C11 - in CRITICAL list
    // === Thread-unsafe functions with static buffers ===
    "strtok",    // Static internal state, data races - use strtok_r
    "asctime",   // Returns static buffer - use strftime
    "ctime",     // Returns static buffer - use strftime
    "gmtime",    // Returns static struct - use gmtime_r
    "localtime", // Returns static struct - use localtime_r
    "strerror",  // May return static buffer - use strerror_r
    // === Environment/system functions with race conditions ===
    "getenv", // Data races, invalidated pointer
    "tmpnam", // TOCTOU race condition - use mkstemp
    // === Numeric conversion without error detection ===
    "atoi",  // No error detection, UB on overflow - use strtol
    "atol",  // No error detection, UB on overflow - use strtol
    "atoll", // No error detection, UB on overflow - use strtoll
    "atof",  // No error detection - use strtod
    // === Multibyte conversion without size validation ===
    "wctomb",   // Static state, not reentrant - use wcrtomb
    "mbstowcs", // No destination size validation - use mbsrtowcs
    "wcstombs", // No destination size validation - use wcsrtombs
    // === Legacy dangerous functions ===
    "getwd",   // Use getcwd instead
    "getpass", // Obsolete, insecure
];

/// Critical banned APIs that are especially dangerous and should never be used.
/// These will cause an Error (not Warning) level result.
const CRITICAL_BANNED_APIS: &[&str] = &[
    "gets",     // REMOVED from C11 - no bounds checking possible
    "strcpy",   // Buffer overflow risk - use strlcpy
    "wcscpy",   // Wide char strcpy
    "strcat",   // Buffer overflow risk - use strlcat
    "wcscat",   // Wide char strcat
    "sprintf",  // Buffer overflow + format string - use snprintf
    "vsprintf", // Buffer overflow + format string - use vsnprintf
];

pub struct DoNotUseBannedApisMachO {
    descriptor: RuleDescriptor,
}

impl DoNotUseBannedApisMachO {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD5013, "DoNotUseBannedApisMachO")
            .with_category(RuleCategory::Security)
            .with_tags(&["hardening", "memory-safety", "macos-only"])
            .with_short_description("Do not use banned/dangerous API functions.")
            .with_full_description(
                "Certain C library functions are known security risks due to lack of bounds \
                 checking or other vulnerabilities. The C17/C23 standards identify these \
                 through Annex K (bounds-checking interfaces). Functions like strcpy, sprintf, \
                 and gets (removed in C11) should be replaced with safer alternatives like \
                 strlcpy (BSD/macOS), snprintf, and fgets.",
            )
            .with_fix_hint(
                "Replace banned functions with safer alternatives (e.g., strlcpy, snprintf)",
            )
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' does not use critically banned API functions.",
            )
            .with_message(
                "Warning",
                "'{0}' uses banned API functions: {1}. Consider using safer alternatives.",
            )
            .with_message(
                "Error_Critical",
                "'{0}' uses critically dangerous API functions: {1}. These must be replaced.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for DoNotUseBannedApisMachO {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DoNotUseBannedApisMachO {
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

        // Check for critical banned APIs first (using exact match to avoid false positives)
        let critical_found: Vec<&str> = CRITICAL_BANNED_APIS
            .iter()
            .filter(|api| macho.has_symbol_exact(api))
            .copied()
            .collect();

        if !critical_found.is_empty() {
            let apis = critical_found.join(", ");
            self.log_fail(
                context,
                FailureLevel::Error,
                "Error_Critical",
                &[&file_name, &apis],
            );
            return;
        }

        // Check for other banned APIs (using exact match to avoid false positives)
        let banned_found: Vec<&str> = BANNED_APIS
            .iter()
            .filter(|api| macho.has_symbol_exact(api))
            .copied()
            .collect();

        if !banned_found.is_empty() {
            let apis = banned_found.join(", ");
            self.log_fail(
                context,
                FailureLevel::Warning,
                "Warning",
                &[&file_name, &apis],
            );
        } else {
            self.log_pass(context, "Pass", &[&file_name]);
        }
    }
}
