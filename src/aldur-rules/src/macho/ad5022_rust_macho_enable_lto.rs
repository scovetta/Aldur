//! AD5022: RustMachOEnableLTO
//!
//! Checks that Rust Mach-O binaries are compiled with Link-Time Optimization (LTO).
//! LTO enables additional security and performance optimizations across compilation units.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{DwarfInfo, MachOBinary};

use crate::rule_ids::AD5022;

pub struct RustMachOEnableLTO {
    descriptor: RuleDescriptor,
}

impl RustMachOEnableLTO {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD5022, "RustMachOEnableLTO")
            .with_category(RuleCategory::Performance)
            .with_tags(&["recommended", "macos-only"])
            .with_short_description("Enable Link-Time Optimization (LTO) for Rust Mach-O binaries.")
            .with_full_description(
                "Link-Time Optimization (LTO) performs optimization across all compilation \
                 units at link time. For Rust, this enables whole-program optimization \
                 that can improve performance and reduce binary size. LTO also enables \
                 better dead code elimination. Enable with '-C lto' in rustc, or set \
                 'lto = true' in Cargo.toml's profile section.",
            )
            .with_fix_hint("Set lto = true in Cargo.toml [profile.release]")
            .with_default_level(FailureLevel::Note)
            .with_message(
                "Pass",
                "'{0}' is a Rust Mach-O binary compiled with Link-Time Optimization.",
            )
            .with_message(
                "Note",
                "'{0}' is a Rust Mach-O binary that was not compiled with LTO. Consider using \
                 '-C lto' or setting 'lto = true' in Cargo.toml for performance benefits.",
            )
            .with_message(
                "NotApplicable_NoDebugInfo",
                "'{0}' does not contain debug information to determine LTO usage.",
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

    /// LTO-related symbols that indicate LTO was used
    const LTO_SYMBOLS: &'static [&'static str] = &[
        ".llvm.lto",
        "__llvm_lto",
        "llvm.used",
        ".lto_discard",
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
                    || cu.compiler_info.language
                        == aldur_parsers::dwarf::DwarfLanguage::Rust
                {
                    return true;
                }
            }
        }

        false
    }

    /// Check for LTO in DWARF producer strings
    fn check_lto_in_dwarf(dwarf: &DwarfInfo) -> LtoResult {
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
            return LtoResult::NotRust;
        }

        // Check for LTO flags in producer strings
        for cu in &rust_units {
            let producer = &cu.compiler_info.producer;

            // Check for Rust-specific LTO flags
            if producer.contains("-C lto")
                || producer.contains("-Clto")
                || producer.contains("lto=yes")
                || producer.contains("lto=thin")
                || producer.contains("lto=fat")
                || producer.contains("-flto")
            {
                return LtoResult::LtoEnabled;
            }
        }

        // Also use the generic DWARF LTO check
        if dwarf.has_lto() {
            return LtoResult::LtoEnabled;
        }

        LtoResult::LtoNotDetected
    }

    /// Check for LTO symbols in the binary
    fn has_lto_symbols(macho: &MachOBinary) -> bool {
        macho.has_any_symbol(Self::LTO_SYMBOLS)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LtoResult {
    LtoEnabled,
    LtoNotDetected,
    NotRust,
}

impl Default for RustMachOEnableLTO {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for RustMachOEnableLTO {
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

        // First check for LTO symbols
        if Self::has_lto_symbols(macho) {
            self.log_pass(context, "Pass", &[&file_name]);
            return;
        }

        // Try to parse DWARF info to check for LTO
        let dwarf = match DwarfInfo::parse(macho.data()) {
            Ok(dwarf) => dwarf,
            Err(_) => {
                // No debug info available - can't definitively check for LTO
                self.log_not_applicable(context, "NotApplicable_NoDebugInfo", &[&file_name]);
                return;
            }
        };

        if dwarf.compilation_units.is_empty() {
            self.log_not_applicable(context, "NotApplicable_NoDebugInfo", &[&file_name]);
            return;
        }

        match Self::check_lto_in_dwarf(&dwarf) {
            LtoResult::LtoEnabled => {
                self.log_pass(context, "Pass", &[&file_name]);
            }
            LtoResult::LtoNotDetected => {
                self.log_fail(context, FailureLevel::Note, "Note", &[&file_name]);
            }
            LtoResult::NotRust => {
                self.log_not_applicable(context, "NotApplicable_NotRust", &[&file_name]);
            }
        }
    }
}
