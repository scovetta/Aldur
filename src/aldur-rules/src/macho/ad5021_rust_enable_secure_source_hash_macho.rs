//! AD5021: RustEnableSecureSourceHashMachO
//!
//! Verifies Rust Mach-O binaries use SHA256 for source file hashing.
//! For Rust, this is enabled with -Z src-hash-algorithm=sha256.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{DwarfInfo, MachOBinary};

use crate::rule_ids::AD5021;

pub struct RustEnableSecureSourceHashMachO {
    descriptor: RuleDescriptor,
}

impl RustEnableSecureSourceHashMachO {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD5021, "RustEnableSecureSourceHashMachO")
            .with_category(RuleCategory::Security)
            .with_tags(&["nightly", "macos-only"])
            .with_short_description("Use secure source file hashing for Rust Mach-O binaries.")
            .with_full_description(
                "Rust binaries should use SHA256 for source file hashing instead of the \
                 default MD5. This ensures stronger integrity verification of source files \
                 in debug information. Use the unstable flag '-Z src-hash-algorithm=sha256' \
                 to enable secure hashing. This requires a nightly Rust compiler.",
            )
            .with_fix_hint("Use RUSTFLAGS='-Z src-hash-algorithm=sha256' (nightly only)")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' is a Rust Mach-O binary with secure source hashing (SHA256).",
            )
            .with_message(
                "Pass_NoDebugInfo",
                "'{0}' has no debug information containing source hashes.",
            )
            .with_message(
                "Warning_InsecureHash",
                "'{0}' is a Rust Mach-O binary that may be using MD5 for source file hashing. \
                 Consider compiling with '-Z src-hash-algorithm=sha256' to use secure hashing. \
                 Note: This requires a nightly Rust compiler.",
            )
            .with_message(
                "Warning_UnknownHash",
                "'{0}' is a Rust Mach-O binary but the source hash algorithm could not be determined. \
                 Consider compiling with '-Z src-hash-algorithm=sha256' for secure hashing.",
            )
            .with_message(
                "NotApplicable_NotRust",
                "'{0}' is not a Rust binary.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }

    /// Rust-specific symbols to identify Rust binaries
    const RUST_SYMBOLS: &'static [&'static str] = &[
        "rust_begin_unwind",
        "rust_panic",
        "__rust_alloc",
        "__rust_dealloc",
        "__rust_realloc",
        "_RNvCs", // Rust v0 mangled symbol prefix
    ];

    /// Check if the binary is a Rust binary by looking for Rust-specific symbols or DWARF info
    fn is_rust_binary(macho: &MachOBinary) -> bool {
        // Check for Rust-specific symbols
        if macho.has_any_symbol(Self::RUST_SYMBOLS) {
            return true;
        }

        // Also check DWARF info for rustc producer
        if let Ok(dwarf) = DwarfInfo::parse(macho.data()) {
            for cu in &dwarf.compilation_units {
                if cu.compiler_info.producer.contains("rustc")
                    || cu.compiler_info.language == aldur_parsers::dwarf::DwarfLanguage::Rust
                {
                    return true;
                }
            }
        }

        false
    }

    /// Check for SHA256 source hashing in DWARF info
    fn check_source_hash_algorithm(dwarf: &DwarfInfo) -> SourceHashResult {
        // Look for Rust compilation units
        let rust_units: Vec<_> = dwarf
            .compilation_units
            .iter()
            .filter(|cu| {
                cu.compiler_info.language == aldur_parsers::dwarf::DwarfLanguage::Rust
                    || cu.compiler_info.producer.contains("rustc")
            })
            .collect();

        if rust_units.is_empty() {
            return SourceHashResult::NotRust;
        }

        // Check for -Z src-hash-algorithm flag in producer strings
        for cu in &rust_units {
            let producer = &cu.compiler_info.producer;

            // Check for explicit sha256 flag
            if producer.contains("src-hash-algorithm=sha256")
                || producer.contains("src_hash_algorithm=sha256")
            {
                return SourceHashResult::SecureHash;
            }

            // Check for explicit sha1 or md5 (insecure)
            if producer.contains("src-hash-algorithm=sha1")
                || producer.contains("src_hash_algorithm=sha1")
                || producer.contains("src-hash-algorithm=md5")
                || producer.contains("src_hash_algorithm=md5")
            {
                return SourceHashResult::InsecureHash;
            }
        }

        // If we found Rust units but no explicit hash algorithm, it's using the default (MD5)
        SourceHashResult::DefaultHash
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceHashResult {
    SecureHash,
    InsecureHash,
    DefaultHash,
    NotRust,
}

impl Default for RustEnableSecureSourceHashMachO {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for RustEnableSecureSourceHashMachO {
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

        // Only applicable to Rust binaries
        if !Self::is_rust_binary(macho) {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Not a Rust binary".to_string()),
            );
        }

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

        // Verify it's a Rust binary
        if !Self::is_rust_binary(macho) {
            self.log_not_applicable(context, "NotApplicable_NotRust", &[&file_name]);
            return;
        }

        // Try to parse DWARF info
        let dwarf = match DwarfInfo::parse(macho.data()) {
            Ok(dwarf) => dwarf,
            Err(_) => {
                // No debug info available - can't check source hashing
                self.log_pass(context, "Pass_NoDebugInfo", &[&file_name]);
                return;
            }
        };

        if !dwarf.has_debug_info {
            self.log_pass(context, "Pass_NoDebugInfo", &[&file_name]);
            return;
        }

        match Self::check_source_hash_algorithm(&dwarf) {
            SourceHashResult::SecureHash => {
                self.log_pass(context, "Pass", &[&file_name]);
            }
            SourceHashResult::InsecureHash => {
                self.log_fail(
                    context,
                    FailureLevel::Warning,
                    "Warning_InsecureHash",
                    &[&file_name],
                );
            }
            SourceHashResult::DefaultHash => {
                self.log_fail(
                    context,
                    FailureLevel::Warning,
                    "Warning_InsecureHash",
                    &[&file_name],
                );
            }
            SourceHashResult::NotRust => {
                self.log_not_applicable(context, "NotApplicable_NotRust", &[&file_name]);
            }
        }
    }
}
