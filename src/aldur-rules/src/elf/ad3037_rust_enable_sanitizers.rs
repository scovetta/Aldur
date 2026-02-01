//! AD3037: RustEnableSanitizers
//!
//! Detects sanitizer instrumentation in Rust binaries for debug/test builds.
//! Sanitizers include ASan, MSan, TSan, and UBSan.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::ElfBinary;

use crate::rule_ids::AD3037;

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
    /// Control Flow Integrity
    Cfi,
    /// Memory Tagging (MTE)
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

pub struct RustEnableSanitizers {
    descriptor: RuleDescriptor,
}

impl RustEnableSanitizers {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD3037, "RustEnableSanitizers")
            .with_category(RuleCategory::Security)
            .with_tags(&["nightly"])
            .with_short_description("Report sanitizer instrumentation in Rust binaries.")
            .with_full_description(
                "This rule detects sanitizer instrumentation in Rust binaries. Sanitizers \
                 are powerful tools for finding bugs during testing. For Rust, enable \
                 sanitizers with '-Zsanitizer=address', '-Zsanitizer=memory', \
                 '-Zsanitizer=thread', '-Zsanitizer=leak', '-Zsanitizer=cfi' (requires LTO), \
                 or '-Zsanitizer=memtag' (ARM64 only). Note that sanitizers \
                 should typically only be used in debug/test builds due to performance \
                 overhead. This rule reports which sanitizers are detected.",
            )
            .with_fix_hint("Use RUSTFLAGS='-Zsanitizer=address' (nightly only)")
            .with_default_level(FailureLevel::Note)
            .with_message(
                "Pass",
                "'{0}' is a Rust binary with sanitizer instrumentation: {1}.",
            )
            .with_message(
                "Note_NoSanitizers",
                "'{0}' is a Rust binary without sanitizer instrumentation. For debug/test \
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

    /// HardwareAddressSanitizer symbols
    const HWASAN_SYMBOLS: &'static [&'static str] = &[
        "__hwasan_init",
        "__hwasan_tag_memory",
        "__hwasan_check",
        "__hwasan_load",
        "__hwasan_store",
    ];

    /// LeakSanitizer symbols
    const LSAN_SYMBOLS: &'static [&'static str] = &[
        "__lsan_init",
        "__lsan_register_root_region",
        "__lsan_do_leak_check",
        "__lsan_ignore_object",
    ];

    /// Control Flow Integrity (CFI) symbols
    /// CFI is enabled with -Zsanitizer=cfi and requires LTO
    const CFI_SYMBOLS: &'static [&'static str] = &[
        "__cfi_check",
        "__cfi_slowpath",
        "__cfi_slowpath_diag",
        "__cfi_check_fail",
        ".cfi", // CFI-related section marker
    ];

    /// Memory Tagging Extension (MTE) symbols
    /// MTE is ARM64-specific, enabled with -Zsanitizer=memtag
    const MTE_SYMBOLS: &'static [&'static str] = &[
        "__memtag_init",
        "__arm_mte_",
        "__mte_",
        "__memtag_handle",
        "memtag_handle_mismatch",
    ];

    /// Detect which sanitizers are present in the binary
    fn detect_sanitizers(elf: &ElfBinary) -> Vec<SanitizerType> {
        let mut sanitizers = Vec::new();

        if elf.has_any_symbol(Self::ASAN_SYMBOLS) {
            sanitizers.push(SanitizerType::Address);
        }

        if elf.has_any_symbol(Self::MSAN_SYMBOLS) {
            sanitizers.push(SanitizerType::Memory);
        }

        if elf.has_any_symbol(Self::TSAN_SYMBOLS) {
            sanitizers.push(SanitizerType::Thread);
        }

        if elf.has_any_symbol(Self::UBSAN_SYMBOLS) {
            sanitizers.push(SanitizerType::UndefinedBehavior);
        }

        if elf.has_any_symbol(Self::HWASAN_SYMBOLS) {
            sanitizers.push(SanitizerType::HardwareAddress);
        }

        if elf.has_any_symbol(Self::LSAN_SYMBOLS) {
            sanitizers.push(SanitizerType::Leak);
        }

        if elf.has_any_symbol(Self::CFI_SYMBOLS) {
            sanitizers.push(SanitizerType::Cfi);
        }

        if elf.has_any_symbol(Self::MTE_SYMBOLS) {
            sanitizers.push(SanitizerType::MemoryTag);
        }

        sanitizers
    }
}

impl Default for RustEnableSanitizers {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for RustEnableSanitizers {
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

        // Only applicable to Rust binaries
        if !elf.is_rust_binary {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Not a Rust binary".to_string()),
            );
        }

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

        // Verify it's a Rust binary
        if !elf.is_rust_binary {
            self.log_not_applicable(context, "NotApplicable_NotRust", &[&file_name]);
            return;
        }

        let sanitizers = Self::detect_sanitizers(elf);

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
