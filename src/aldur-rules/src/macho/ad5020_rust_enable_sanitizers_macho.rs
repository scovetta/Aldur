//! AD5020: RustEnableSanitizersMachO
//!
//! Detects sanitizer instrumentation in Rust Mach-O binaries for debug/test builds.
//! Sanitizers include ASan, MSan, TSan, UBSan, HWASan, LSan, CFI, and MTE.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{DwarfInfo, MachOBinary};

use crate::rule_ids::AD5020;

/// Detected sanitizer types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SanitizerType {
    /// Address Sanitizer (ASan)
    Address,
    /// Memory Sanitizer (MSan)
    Memory,
    /// Thread Sanitizer (TSan)
    Thread,
    /// Undefined Behavior Sanitizer (UBSan)
    UndefinedBehavior,
    /// Hardware-assisted Address Sanitizer (HWASan)
    HardwareAddress,
    /// Leak Sanitizer (LSan)
    Leak,
    /// Control Flow Integrity (CFI)
    Cfi,
    /// Memory Tagging (MTE) - ARM64 only
    MemoryTag,
}

impl std::fmt::Display for SanitizerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SanitizerType::Address => write!(f, "AddressSanitizer"),
            SanitizerType::Memory => write!(f, "MemorySanitizer"),
            SanitizerType::Thread => write!(f, "ThreadSanitizer"),
            SanitizerType::UndefinedBehavior => write!(f, "UndefinedBehaviorSanitizer"),
            SanitizerType::HardwareAddress => write!(f, "HWAddressSanitizer"),
            SanitizerType::Leak => write!(f, "LeakSanitizer"),
            SanitizerType::Cfi => write!(f, "ControlFlowIntegrity"),
            SanitizerType::MemoryTag => write!(f, "MemoryTagging"),
        }
    }
}

pub struct RustEnableSanitizersMachO {
    descriptor: RuleDescriptor,
}

impl RustEnableSanitizersMachO {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD5020, "RustEnableSanitizersMachO")
            .with_category(RuleCategory::Security)
            .with_tags(&["nightly", "macos-only"])
            .with_short_description("Report sanitizer instrumentation in Rust Mach-O binaries.")
            .with_full_description(
                "This rule detects sanitizer instrumentation in Rust Mach-O binaries. Sanitizers \
                 are powerful tools for finding bugs during testing. For Rust, enable \
                 sanitizers with '-Zsanitizer=address', '-Zsanitizer=memory', \
                 '-Zsanitizer=thread', '-Zsanitizer=leak', '-Zsanitizer=cfi' (requires LTO), \
                 or '-Zsanitizer=hwaddress' (ARM64). Note that sanitizers \
                 should typically only be used in debug/test builds due to performance \
                 overhead. This rule reports which sanitizers are detected.",
            )
            .with_fix_hint("Use RUSTFLAGS='-Zsanitizer=address' (nightly only)")
            .with_default_level(FailureLevel::Note)
            .with_message(
                "Pass",
                "'{0}' is a Rust Mach-O binary with sanitizer instrumentation: {1}.",
            )
            .with_message(
                "Note_NoSanitizers",
                "'{0}' is a Rust Mach-O binary without sanitizer instrumentation. For debug/test \
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

    /// Rust-specific symbols to identify Rust binaries
    const RUST_SYMBOLS: &'static [&'static str] = &[
        "rust_begin_unwind",
        "rust_panic",
        "__rust_alloc",
        "__rust_dealloc",
        "__rust_realloc",
        "_RNvCs", // Rust v0 mangled symbol prefix
    ];

    /// AddressSanitizer symbols
    const ASAN_SYMBOLS: &'static [&'static str] = &[
        "__asan_init",
        "__asan_version_mismatch",
        "__asan_register_globals",
        "__asan_report_load",
        "__asan_report_store",
        "__asan_stack_malloc",
        "__asan_handle_no_return",
    ];

    /// MemorySanitizer symbols
    const MSAN_SYMBOLS: &'static [&'static str] = &[
        "__msan_init",
        "__msan_warning",
        "__msan_poison",
        "__msan_unpoison",
        "__msan_check_mem_is_initialized",
    ];

    /// ThreadSanitizer symbols
    const TSAN_SYMBOLS: &'static [&'static str] = &[
        "__tsan_init",
        "__tsan_read",
        "__tsan_write",
        "__tsan_func_entry",
        "__tsan_func_exit",
        "__tsan_acquire",
        "__tsan_release",
    ];

    /// LeakSanitizer symbols
    const LSAN_SYMBOLS: &'static [&'static str] = &[
        "__lsan_init",
        "__lsan_register_root_region",
        "__lsan_do_leak_check",
        "__lsan_ignore_object",
    ];

    /// UndefinedBehaviorSanitizer symbols
    const UBSAN_SYMBOLS: &'static [&'static str] = &[
        "__ubsan_handle_add_overflow",
        "__ubsan_handle_sub_overflow",
        "__ubsan_handle_mul_overflow",
        "__ubsan_handle_divrem_overflow",
        "__ubsan_handle_negate_overflow",
        "__ubsan_handle_pointer_overflow",
        "__ubsan_handle_shift_out_of_bounds",
        "__ubsan_handle_type_mismatch",
        "__ubsan_handle_out_of_bounds",
    ];

    /// HardwareAddressSanitizer symbols (ARM64)
    const HWASAN_SYMBOLS: &'static [&'static str] = &[
        "__hwasan_init",
        "__hwasan_tag_memory",
        "__hwasan_check",
        "__hwasan_load",
        "__hwasan_store",
    ];

    /// Control Flow Integrity (CFI) symbols
    const CFI_SYMBOLS: &'static [&'static str] = &[
        "__cfi_check",
        "__cfi_slowpath",
        "__cfi_slowpath_diag",
        "__cfi_check_fail",
    ];

    /// Memory Tagging Extension (MTE) symbols (ARM64)
    const MTE_SYMBOLS: &'static [&'static str] = &[
        "__memtag_init",
        "__arm_mte_",
        "__mte_",
        "__memtag_handle",
        "memtag_handle_mismatch",
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

    /// Detect which sanitizers are present in the binary
    fn detect_sanitizers(macho: &MachOBinary) -> Vec<SanitizerType> {
        let mut sanitizers = Vec::new();

        if macho.has_any_symbol(Self::ASAN_SYMBOLS) {
            sanitizers.push(SanitizerType::Address);
        }

        if macho.has_any_symbol(Self::MSAN_SYMBOLS) {
            sanitizers.push(SanitizerType::Memory);
        }

        if macho.has_any_symbol(Self::TSAN_SYMBOLS) {
            sanitizers.push(SanitizerType::Thread);
        }

        if macho.has_any_symbol(Self::UBSAN_SYMBOLS) {
            sanitizers.push(SanitizerType::UndefinedBehavior);
        }

        if macho.has_any_symbol(Self::HWASAN_SYMBOLS) {
            sanitizers.push(SanitizerType::HardwareAddress);
        }

        if macho.has_any_symbol(Self::LSAN_SYMBOLS) {
            sanitizers.push(SanitizerType::Leak);
        }

        if macho.has_any_symbol(Self::CFI_SYMBOLS) {
            sanitizers.push(SanitizerType::Cfi);
        }

        if macho.has_any_symbol(Self::MTE_SYMBOLS) {
            sanitizers.push(SanitizerType::MemoryTag);
        }

        sanitizers
    }
}

impl Default for RustEnableSanitizersMachO {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for RustEnableSanitizersMachO {
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

        let sanitizers = Self::detect_sanitizers(macho);

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
