//! Compiler detection utilities for ELF rules
//!
//! Provides functions to detect compiler type and determine rule applicability
//! based on what security features each compiler supports.

use aldur_parsers::dwarf::CompilerType;
use aldur_parsers::{DwarfInfo, ElfBinary};

/// Detected compiler from an ELF binary
#[derive(Debug, Clone)]
pub struct DetectedCompiler {
    /// Compiler type
    pub compiler_type: CompilerType,
    /// Compiler name (e.g., "rustc", "clang", "GCC")
    pub name: String,
    /// Whether the detection is definitive (from DWARF) or heuristic
    pub is_definitive: bool,
}

/// Detect the compiler used to build an ELF binary
pub fn detect_compiler(elf: &ElfBinary) -> DetectedCompiler {
    // First, check if it's a Rust binary (fast path)
    if elf.is_rust_binary {
        return DetectedCompiler {
            compiler_type: CompilerType::Rustc,
            name: "rustc".to_string(),
            is_definitive: true,
        };
    }

    // Try to get compiler info from DWARF debug info
    if let Ok(dwarf_info) = DwarfInfo::parse(elf.data()) {
        if dwarf_info.has_debug_info && !dwarf_info.compilation_units.is_empty() {
            for cu in &dwarf_info.compilation_units {
                let producer = &cu.compiler_info.producer;

                if producer.contains("rustc") {
                    return DetectedCompiler {
                        compiler_type: CompilerType::Rustc,
                        name: "rustc".to_string(),
                        is_definitive: true,
                    };
                } else if producer.contains("clang") {
                    return DetectedCompiler {
                        compiler_type: CompilerType::Clang,
                        name: "Clang".to_string(),
                        is_definitive: true,
                    };
                } else if producer.contains("GNU") || producer.contains("GCC") {
                    return DetectedCompiler {
                        compiler_type: CompilerType::Gcc,
                        name: "GCC".to_string(),
                        is_definitive: true,
                    };
                } else if producer.contains("Go") {
                    return DetectedCompiler {
                        compiler_type: CompilerType::Go,
                        name: "Go".to_string(),
                        is_definitive: true,
                    };
                } else if producer.contains("Intel") || producer.contains("ICC") {
                    return DetectedCompiler {
                        compiler_type: CompilerType::Icc,
                        name: "ICC".to_string(),
                        is_definitive: true,
                    };
                }
            }
        }
    }

    // Fall back to heuristic detection
    DetectedCompiler {
        compiler_type: CompilerType::Unknown,
        name: "Unknown".to_string(),
        is_definitive: false,
    }
}

/// Check if a feature is supported by the detected compiler
///
/// Returns Some(reason) if the feature is NOT supported, None if it is supported
pub fn check_compiler_support(
    compiler: &DetectedCompiler,
    feature: CompilerFeature,
) -> Option<String> {
    match feature {
        // Clang-only features
        CompilerFeature::SpeculativeLoadHardening => {
            match compiler.compiler_type {
                CompilerType::Clang => None,
                CompilerType::Rustc => {
                    Some("Speculative Load Hardening is not available in Rust".to_string())
                }
                CompilerType::Gcc => Some(
                    "Speculative Load Hardening is Clang-only; not available in GCC".to_string(),
                ),
                CompilerType::Go => {
                    Some("Speculative Load Hardening is not available in Go".to_string())
                }
                _ => None, // Unknown compiler, check anyway
            }
        }
        CompilerFeature::ClangSafeStack => match compiler.compiler_type {
            CompilerType::Clang => None,
            CompilerType::Rustc => {
                Some("SafeStack is a Clang feature; not available in Rust".to_string())
            }
            CompilerType::Gcc => Some("SafeStack is Clang-only; not available in GCC".to_string()),
            _ => None,
        },
        CompilerFeature::ClangCFI => match compiler.compiler_type {
            CompilerType::Clang => None,
            CompilerType::Rustc => Some(
                "Clang CFI is not available in Rust (use -Z sanitizer=cfi on nightly)".to_string(),
            ),
            CompilerType::Gcc => Some("Clang CFI is not available in GCC".to_string()),
            _ => None,
        },
        // GCC/Clang features not available in Rust (stable)
        CompilerFeature::StackClashProtection => match compiler.compiler_type {
            CompilerType::Gcc | CompilerType::Clang => None,
            CompilerType::Rustc => Some(
                "Stack clash protection (-fstack-clash-protection) is not available in Rust"
                    .to_string(),
            ),
            CompilerType::Go => Some("Stack clash protection is not available in Go".to_string()),
            _ => None,
        },
        CompilerFeature::StackProtector => match compiler.compiler_type {
            CompilerType::Gcc | CompilerType::Clang => None,
            CompilerType::Rustc => {
                Some("GCC/Clang stack protector is not applicable to Rust binaries".to_string())
            }
            _ => None,
        },
        CompilerFeature::Fortify => match compiler.compiler_type {
            CompilerType::Gcc | CompilerType::Clang => None,
            CompilerType::Rustc => {
                Some("FORTIFY_SOURCE is a C/C++ feature; not applicable to Rust".to_string())
            }
            CompilerType::Go => Some("FORTIFY_SOURCE is not applicable to Go".to_string()),
            _ => None,
        },
        // CET features (requires nightly for Rust)
        CompilerFeature::IntelCET => {
            match compiler.compiler_type {
                CompilerType::Gcc | CompilerType::Clang => None,
                // For Rust, we have a separate rule (AD3033) that handles the nightly case
                CompilerType::Rustc => {
                    Some("Intel CET requires Rust nightly with -Z cf-protection=full".to_string())
                }
                _ => None,
            }
        }
    }
}

/// Compiler features that may not be available in all compilers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompilerFeature {
    /// Speculative Load Hardening (Clang only)
    SpeculativeLoadHardening,
    /// SafeStack (Clang only)
    ClangSafeStack,
    /// Clang CFI (Clang only, Rust nightly has separate support)
    ClangCFI,
    /// Stack clash protection (GCC/Clang, not Rust stable)
    StackClashProtection,
    /// Stack protector/canary (GCC/Clang)
    StackProtector,
    /// FORTIFY_SOURCE (C/C++ only)
    Fortify,
    /// Intel CET (GCC/Clang, Rust nightly)
    IntelCET,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compiler_feature_support() {
        let rust_compiler = DetectedCompiler {
            compiler_type: CompilerType::Rustc,
            name: "rustc".to_string(),
            is_definitive: true,
        };

        // SLH should not be supported for Rust
        assert!(
            check_compiler_support(&rust_compiler, CompilerFeature::SpeculativeLoadHardening)
                .is_some()
        );

        let clang_compiler = DetectedCompiler {
            compiler_type: CompilerType::Clang,
            name: "Clang".to_string(),
            is_definitive: true,
        };

        // SLH should be supported for Clang
        assert!(
            check_compiler_support(&clang_compiler, CompilerFeature::SpeculativeLoadHardening)
                .is_none()
        );
    }
}
