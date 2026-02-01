//! Shared utilities for MSVC-specific PE rules
//!
//! This module provides common functionality for detecting whether a PE binary
//! was built with MSVC vs other compilers (Rust, GCC, Clang, etc.)

use aldur_core::Binary;
use aldur_parsers::{DwarfInfo, PeBinary};

/// Check if the binary was built with a non-MSVC compiler (Rust, GCC, Clang, etc.)
/// by examining DWARF debug info. Returns the compiler name if detected.
///
/// MSVC uses CodeView/PDB format for debug info, while other compilers
/// (Rust, GCC, Clang, MinGW) use DWARF even on Windows.
pub fn detect_non_msvc_compiler(pe: &PeBinary) -> Option<String> {
    // If the binary has DWARF debug info, it was likely built with a non-MSVC compiler
    // (MSVC uses CodeView/PDB format, not DWARF)
    if pe.has_dwarf_debug_info() {
        if let Ok(dwarf) = DwarfInfo::load(pe.path()) {
            for cu in &dwarf.compilation_units {
                let producer = &cu.compiler_info.producer;
                if producer.contains("rustc") {
                    return Some("Rust (rustc)".to_string());
                } else if producer.contains("clang") {
                    return Some("Clang".to_string());
                } else if producer.contains("GNU") || producer.contains("GCC") {
                    return Some("GCC".to_string());
                } else if producer.contains("Go") {
                    return Some("Go".to_string());
                }
            }
            // Has DWARF but unknown producer - still not MSVC
            return Some("non-MSVC compiler".to_string());
        }
    }
    None
}

/// Returns true if the PE binary appears to be built with MSVC.
/// This is determined by the absence of DWARF debug info.
#[allow(dead_code)]
pub fn is_likely_msvc_binary(pe: &PeBinary) -> bool {
    detect_non_msvc_compiler(pe).is_none()
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_is_likely_msvc_binary_no_dwarf() {
        // This is a unit test for the logic - actual binary tests are in integration tests
    }
}
