//! AD2041: RustEnableSanitizersPE
//!
//! Detects sanitizer instrumentation in Rust PE binaries for debug/test builds.
//! Sanitizers include ASan, TSan, UBSan, LSan, and CFI.
//! Note: MSan and MTE are not supported on Windows.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, Binary, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{DwarfInfo, PeBinary};

use crate::rule_ids::AD2041;

/// Detected sanitizer types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SanitizerType {
    /// Address Sanitizer (ASan)
    Address,
    /// Thread Sanitizer (TSan)
    Thread,
    /// Undefined Behavior Sanitizer (UBSan)
    UndefinedBehavior,
    /// Leak Sanitizer (LSan)
    Leak,
    /// Control Flow Integrity (CFI)
    Cfi,
}

impl std::fmt::Display for SanitizerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SanitizerType::Address => write!(f, "AddressSanitizer"),
            SanitizerType::Thread => write!(f, "ThreadSanitizer"),
            SanitizerType::UndefinedBehavior => write!(f, "UndefinedBehaviorSanitizer"),
            SanitizerType::Leak => write!(f, "LeakSanitizer"),
            SanitizerType::Cfi => write!(f, "ControlFlowIntegrity"),
        }
    }
}

pub struct RustEnableSanitizersPE {
    descriptor: RuleDescriptor,
}

impl RustEnableSanitizersPE {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2041, "RustEnableSanitizersPE")
            .with_category(RuleCategory::Security)
            .with_tags(&["nightly", "windows-only"])
            .with_short_description("Report sanitizer instrumentation in Rust PE binaries.")
            .with_full_description(
                "This rule detects sanitizer instrumentation in Rust PE (Windows) binaries. \
                 Sanitizers are powerful tools for finding bugs during testing. For Rust on \
                 Windows, enable sanitizers with '-Zsanitizer=address', '-Zsanitizer=thread', \
                 '-Zsanitizer=leak', or '-Zsanitizer=cfi' (requires LTO). Note: MemorySanitizer \
                 and MemoryTagging (MTE) are not supported on Windows. Sanitizers should \
                 typically only be used in debug/test builds due to performance overhead.",
            )
            .with_fix_hint("Use RUSTFLAGS='-Zsanitizer=address' (nightly only)")
            .with_default_level(FailureLevel::Note)
            .with_message(
                "Pass",
                "'{0}' is a Rust PE binary with sanitizer instrumentation: {1}.",
            )
            .with_message(
                "Note_NoSanitizers",
                "'{0}' is a Rust PE binary without sanitizer instrumentation. For debug/test \
                 builds, consider using '-Zsanitizer=address' or other sanitizers to detect \
                 memory safety issues.",
            )
            .with_message("NotApplicable_NotRust", "'{0}' is not a Rust binary.")
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }

    // Note: Unlike ELF/Mach-O, PE binaries don't expose symbol tables easily.
    // Detection is done through DWARF debug info and compiler flags instead.

    /// Check if the binary is a Rust binary by looking for DWARF info
    fn is_rust_binary(pe: &PeBinary) -> bool {
        // Check for DWARF debug info with Rust producer
        if pe.has_dwarf_debug_info() {
            if let Ok(dwarf) = DwarfInfo::load(pe.path()) {
                for cu in &dwarf.compilation_units {
                    if cu.compiler_info.producer.contains("rustc")
                        || cu.compiler_info.language == aldur_parsers::dwarf::DwarfLanguage::Rust
                    {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Check for sanitizer symbols in DWARF debug info
    fn has_sanitizer_symbols_in_dwarf(pe: &PeBinary, symbols: &[&str]) -> bool {
        if !pe.has_dwarf_debug_info() {
            return false;
        }

        if let Ok(dwarf) = DwarfInfo::load(pe.path()) {
            for cu in &dwarf.compilation_units {
                // Check producer string for sanitizer flags
                let producer = &cu.compiler_info.producer;
                for symbol in symbols {
                    // For PE, check if sanitizer flags are present in producer/flags
                    if producer.contains(symbol) {
                        return true;
                    }
                }
                // Also check parsed flags
                for flag in &cu.parsed_info.flags {
                    for symbol in symbols {
                        if flag.contains(symbol) {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    /// Detect which sanitizers are present in the binary
    fn detect_sanitizers(pe: &PeBinary) -> Vec<SanitizerType> {
        let mut sanitizers = Vec::new();

        // Check for sanitizer flags in DWARF debug info
        if Self::has_sanitizer_symbols_in_dwarf(pe, &["sanitize=address", "asan"]) {
            sanitizers.push(SanitizerType::Address);
        }

        if Self::has_sanitizer_symbols_in_dwarf(pe, &["sanitize=thread", "tsan"]) {
            sanitizers.push(SanitizerType::Thread);
        }

        if Self::has_sanitizer_symbols_in_dwarf(pe, &["sanitize=undefined", "ubsan"]) {
            sanitizers.push(SanitizerType::UndefinedBehavior);
        }

        if Self::has_sanitizer_symbols_in_dwarf(pe, &["sanitize=leak", "lsan"]) {
            sanitizers.push(SanitizerType::Leak);
        }

        if Self::has_sanitizer_symbols_in_dwarf(pe, &["sanitize=cfi", "cfi"]) {
            sanitizers.push(SanitizerType::Cfi);
        }

        sanitizers
    }
}

impl Default for RustEnableSanitizersPE {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for RustEnableSanitizersPE {
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

        let pe = match binary.as_ref().as_any().downcast_ref::<PeBinary>() {
            Some(pe) => pe,
            None => {
                return (
                    AnalysisApplicability::NotApplicableToSpecifiedTarget,
                    Some("Could not access PE data".to_string()),
                );
            }
        };

        // Only applicable to Rust binaries with DWARF debug info
        if !pe.has_dwarf_debug_info() {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("PE binary does not have DWARF debug info".to_string()),
            );
        }

        if !Self::is_rust_binary(pe) {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Not a Rust binary".to_string()),
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

        // Verify it's a Rust binary
        if !Self::is_rust_binary(pe) {
            self.log_not_applicable(context, "NotApplicable_NotRust", &[&file_name]);
            return;
        }

        let sanitizers = Self::detect_sanitizers(pe);

        if sanitizers.is_empty() {
            self.log_fail(
                context,
                FailureLevel::Note,
                "Note_NoSanitizers",
                &[&file_name],
            );
        } else {
            let sanitizer_list: String = sanitizers
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            self.log_pass(context, "Pass", &[&file_name, &sanitizer_list]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_descriptor() {
        let rule = RustEnableSanitizersPE::new();
        assert_eq!(rule.descriptor().id, "AD2041");
        assert_eq!(rule.descriptor().name, "RustEnableSanitizersPE");
    }

    #[test]
    fn test_default_level() {
        let rule = RustEnableSanitizersPE::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Note);
    }

    #[test]
    fn test_sanitizer_type_display() {
        assert_eq!(format!("{}", SanitizerType::Address), "AddressSanitizer");
        assert_eq!(format!("{}", SanitizerType::Thread), "ThreadSanitizer");
        assert_eq!(
            format!("{}", SanitizerType::UndefinedBehavior),
            "UndefinedBehaviorSanitizer"
        );
        assert_eq!(format!("{}", SanitizerType::Leak), "LeakSanitizer");
        assert_eq!(format!("{}", SanitizerType::Cfi), "ControlFlowIntegrity");
    }
}
