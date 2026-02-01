//! AD2043: DoNotUseBannedApisPE
//!
//! Checks that PE binaries do not use known dangerous/banned API functions.
//! These functions are prone to buffer overflows and other security vulnerabilities.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::PeBinary;

use crate::rule_ids::AD2043;

/// Banned API functions that are known security risks (C17/C23 standards + Microsoft SDL)
const BANNED_APIS: &[&str] = &[
    // === String operations without bounds checking ===
    "strcpy",
    "strcpyA",
    "strcpyW",
    "wcscpy",
    "lstrcpy",
    "lstrcpyA",
    "lstrcpyW",
    "StrCpy",
    "StrCpyA",
    "StrCpyW",
    "strcat",
    "strcatA",
    "strcatW",
    "wcscat",
    "lstrcat",
    "lstrcatA",
    "lstrcatW",
    "StrCat",
    "StrCatA",
    "StrCatW",
    "strncpy",
    "wcsncpy",
    "strncat",
    "wcsncat",
    // === Format string functions (buffer overflow + format string attacks) ===
    "sprintf",
    "swprintf",
    "vsprintf",
    "vswprintf",
    "wvsprintf",
    "wvsprintfA",
    "wvsprintfW",
    "wsprintf",
    "wsprintfA",
    "wsprintfW",
    // === Dangerous scanf variants (no bounds on %s) ===
    "scanf",
    "wscanf",
    "sscanf",
    "swscanf",
    "fscanf",
    "fwscanf",
    "vscanf",
    "vfscanf",
    "vsscanf",
    "vwscanf",
    "vfwscanf",
    "vswscanf",
    // === Input functions (buffer overflow) ===
    "gets",
    "_getws",
    // === Memory functions without size validation ===
    "memcpy",  // No overlap checking, no size validation - use memcpy_s
    "memmove", // No size validation - use memmove_s
    // === Thread-unsafe functions with static buffers ===
    "strtok", // Static internal state, data races - use strtok_s
    "wcstok",
    "asctime",   // Returns static buffer - use asctime_s
    "ctime",     // Returns static buffer - use ctime_s
    "gmtime",    // Returns static struct - use gmtime_s
    "localtime", // Returns static struct - use localtime_s
    "strerror",  // May return static buffer - use strerror_s
    // === Environment/system functions with race conditions ===
    "getenv", // Data races, invalidated pointer - use getenv_s
    "tmpnam", // TOCTOU race condition - use tmpnam_s
    // === Numeric conversion without error detection ===
    "atoi",  // No error detection, UB on overflow - use strtol
    "atol",  // No error detection, UB on overflow - use strtol
    "atoll", // No error detection, UB on overflow - use strtoll
    "atof",  // No error detection - use strtod
    // === Multibyte conversion without size validation ===
    "wctomb",   // Static state, not reentrant - use wctomb_s
    "mbstowcs", // No destination size validation - use mbstowcs_s
    "wcstombs", // No destination size validation - use wcstombs_s
    // === Other dangerous functions ===
    "alloca",
    "_alloca",
    "makepath",
    "_makepath",
    "_wmakepath",
    "splitpath",
    "_splitpath",
    "_wsplitpath",
];

/// Critical banned APIs that are especially dangerous (removed from C standard or guaranteed overflow)
const CRITICAL_BANNED_APIS: &[&str] = &[
    "gets",     // REMOVED from C11 - no bounds checking possible
    "_getws",   // Wide char version of gets
    "strcpy",   // Buffer overflow risk - use strcpy_s or StringCchCopy
    "wcscpy",   // Wide char strcpy
    "lstrcpy",  // Windows strcpy
    "strcat",   // Buffer overflow risk - use strcat_s or StringCchCat
    "wcscat",   // Wide char strcat
    "lstrcat",  // Windows strcat
    "sprintf",  // Buffer overflow + format string - use snprintf or sprintf_s
    "vsprintf", // Buffer overflow + format string - use vsnprintf or vsprintf_s
    "wsprintf", // Windows sprintf
];

pub struct DoNotUseBannedApisPE {
    descriptor: RuleDescriptor,
}

impl DoNotUseBannedApisPE {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2043, "DoNotUseBannedApisPE")
            .with_category(RuleCategory::Security)
            .with_tags(&["hardening", "memory-safety", "windows-only"])
            .with_short_description("Do not use banned/dangerous API functions.")
            .with_full_description(
                "Certain C library and Windows API functions are known security risks due to \
                 lack of bounds checking or other vulnerabilities. The C17/C23 standards \
                 identify these through Annex K (bounds-checking interfaces). Functions like \
                 strcpy, sprintf, and gets (removed in C11) should be replaced with safer \
                 alternatives like strcpy_s, snprintf, or Windows StringCchCopy. See also \
                 Microsoft's SDL banned function list.",
            )
            .with_fix_hint("Replace banned APIs with safer alternatives (e.g., strcpy_s, snprintf, StringCchCopy)")
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

impl Default for DoNotUseBannedApisPE {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DoNotUseBannedApisPE {
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

        if binary.format() != BinaryFormat::PE {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Not a PE binary".to_string()),
            );
        }

        (AnalysisApplicability::ApplicableToSpecifiedTarget, None)
    }

    fn analyze(&self, context: &mut AnalysisContext) {
        let file_name = context.file_name();
        let binary = context.binary().expect("Binary must be loaded").clone();

        let pe = match binary.as_ref().as_any().downcast_ref::<PeBinary>() {
            Some(pe) => pe,
            None => {
                self.log_not_applicable(
                    context,
                    "NotApplicable_InvalidMetadata",
                    &[&file_name, self.name(), "Could not access PE data"],
                );
                return;
            }
        };

        // Check for critical banned APIs first (check imports)
        let critical_found: Vec<&str> = CRITICAL_BANNED_APIS
            .iter()
            .filter(|api| pe.has_import(api))
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

        // Check for other banned APIs
        let banned_found: Vec<&str> = BANNED_APIS
            .iter()
            .filter(|api| pe.has_import(api))
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
