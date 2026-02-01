//! Packer detection for PE, ELF, and Mach-O binaries
//!
//! This module detects if a binary has been packed or compressed using common
//! executable packers like UPX, ASPack, PECompact, etc.
//!
//! Packed binaries strip or encrypt section headers, debug info, and symbol tables,
//! making security analysis unreliable. When a packer is detected, analysis results
//! should be treated with caution.

use std::collections::HashSet;

/// Known packer types
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PackerType {
    /// UPX - Ultimate Packer for eXecutables
    Upx,
    /// ASPack
    ASPack,
    /// PECompact
    PECompact,
    /// Themida / WinLicense
    Themida,
    /// VMProtect
    VMProtect,
    /// Enigma Protector
    Enigma,
    /// MPRESS
    Mpress,
    /// Petite
    Petite,
    /// FSG (Fast Small Good)
    Fsg,
    /// NSPack
    NsPack,
    /// kkrunchy
    Kkrunchy,
    /// .NET Reactor
    DotNetReactor,
    /// ConfuserEx (.NET)
    ConfuserEx,
    /// Unknown packer detected by heuristics
    Unknown(String),
}

impl PackerType {
    /// Get a human-readable name for the packer
    pub fn name(&self) -> &str {
        match self {
            PackerType::Upx => "UPX",
            PackerType::ASPack => "ASPack",
            PackerType::PECompact => "PECompact",
            PackerType::Themida => "Themida/WinLicense",
            PackerType::VMProtect => "VMProtect",
            PackerType::Enigma => "Enigma Protector",
            PackerType::Mpress => "MPRESS",
            PackerType::Petite => "Petite",
            PackerType::Fsg => "FSG",
            PackerType::NsPack => "NSPack",
            PackerType::Kkrunchy => "kkrunchy",
            PackerType::DotNetReactor => ".NET Reactor",
            PackerType::ConfuserEx => "ConfuserEx",
            PackerType::Unknown(name) => name,
        }
    }

    /// Get the unpacking instructions for this packer
    pub fn unpack_instructions(&self) -> Option<&'static str> {
        match self {
            PackerType::Upx => Some("upx -d <binary>"),
            PackerType::ASPack => Some("Use AspackDie or manual unpacking"),
            PackerType::PECompact => Some("Use unpecompact or manual unpacking"),
            PackerType::Mpress => Some("upx -d <binary> (UPX can sometimes unpack MPRESS)"),
            _ => None,
        }
    }
}

impl std::fmt::Display for PackerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Information about detected packers
#[derive(Debug, Clone, Default)]
pub struct PackerInfo {
    /// Whether the binary appears to be packed
    pub is_packed: bool,
    /// Detected packer types (may detect multiple signatures)
    pub packers: Vec<PackerType>,
    /// Detection confidence (0.0 - 1.0)
    pub confidence: f32,
    /// Raw signatures found
    pub signatures: Vec<String>,
}

impl PackerInfo {
    /// Create an empty (unpacked) PackerInfo
    pub fn none() -> Self {
        Self::default()
    }

    /// Create a PackerInfo with detected packer(s)
    pub fn detected(packers: Vec<PackerType>, confidence: f32, signatures: Vec<String>) -> Self {
        Self {
            is_packed: !packers.is_empty(),
            packers,
            confidence,
            signatures,
        }
    }

    /// Get a comma-separated list of detected packer names
    pub fn packer_names(&self) -> String {
        self.packers
            .iter()
            .map(|p| p.name())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Build a signature pattern at runtime to avoid embedding it in our binary
/// This prevents false positive self-detection
fn build_upx_info_signature() -> Vec<u8> {
    // Build the pattern: "$Info: This file is packed with the UPX"
    // We split it to avoid the compiler embedding the complete string
    let mut sig = Vec::with_capacity(50);
    sig.extend_from_slice(b"$Info: This file is ");
    sig.extend_from_slice(b"packed with the ");
    sig.extend_from_slice(b"UPX");
    sig
}

/// Detect packers in binary data
pub fn detect_packer(data: &[u8], section_names: &[&str]) -> PackerInfo {
    let mut packers = HashSet::new();
    let mut signatures = Vec::new();
    let mut confidence = 0.0f32;

    // === UPX Detection ===
    // UPX stores its signature in specific locations, not just anywhere in the binary.
    // The most reliable detection is section names and the packed info string.
    // We avoid detecting "UPX!" alone as it can appear in code that references UPX.

    // UPX section names are the most reliable indicator
    if section_names.iter().any(|s| *s == "UPX0" || *s == "UPX1" || *s == "UPX2") {
        packers.insert(PackerType::Upx);
        signatures.push("UPX section name".to_string());
        confidence = confidence.max(1.0);
    }

    // UPX info string is a very reliable indicator (only present in packed binaries)
    // We build the pattern at runtime to avoid self-detection
    let upx_info_sig = build_upx_info_signature();
    if has_signature(data, &upx_info_sig) {
        packers.insert(PackerType::Upx);
        signatures.push("UPX info string".to_string());
        confidence = confidence.max(1.0);
    }

    // Check for UPX decompression stub signature at the beginning of sections
    // The "UPX!" magic at the end of the file (last 24 bytes) is used by UPX for decompression
    if data.len() > 24 {
        let tail = &data[data.len().saturating_sub(24)..];
        if tail.windows(4).any(|w| w == b"UPX!") {
            packers.insert(PackerType::Upx);
            signatures.push("UPX trailer magic".to_string());
            confidence = confidence.max(0.95);
        }
    }

    // === Section-based Detection (most reliable, no false positives) ===
    // These are the most reliable indicators as section names won't appear
    // as regular strings in the binary data.

    // ASPack sections
    if section_names.iter().any(|s| *s == ".aspack" || *s == ".adata") {
        packers.insert(PackerType::ASPack);
        signatures.push("ASPack section name".to_string());
        confidence = confidence.max(0.95);
    }

    // PECompact sections
    if section_names.iter().any(|s| *s == ".pec1" || *s == ".pec2") {
        packers.insert(PackerType::PECompact);
        signatures.push("PECompact section name".to_string());
        confidence = confidence.max(0.95);
    }

    // Themida/WinLicense sections
    if section_names.iter().any(|s| *s == ".themida" || s.starts_with(".Themida")) {
        packers.insert(PackerType::Themida);
        signatures.push("Themida section name".to_string());
        confidence = confidence.max(0.95);
    }

    // VMProtect sections
    if section_names.iter().any(|s| s.starts_with(".vmp") || *s == "VMP0" || *s == "VMP1") {
        packers.insert(PackerType::VMProtect);
        signatures.push("VMProtect section name".to_string());
        confidence = confidence.max(0.95);
    }

    // Enigma Protector sections
    if section_names.iter().any(|s| s.starts_with(".enigma")) {
        packers.insert(PackerType::Enigma);
        signatures.push("Enigma section name".to_string());
        confidence = confidence.max(0.95);
    }

    // MPRESS sections
    if section_names.iter().any(|s| *s == ".MPRESS1" || *s == ".MPRESS2") {
        packers.insert(PackerType::Mpress);
        signatures.push("MPRESS section name".to_string());
        confidence = confidence.max(0.95);
    }

    // Petite sections
    if section_names.iter().any(|s| *s == ".petite") {
        packers.insert(PackerType::Petite);
        signatures.push("Petite section name".to_string());
        confidence = confidence.max(0.95);
    }

    // FSG sections
    if section_names.iter().any(|s| *s == "FSG!") {
        packers.insert(PackerType::Fsg);
        signatures.push("FSG section name".to_string());
        confidence = confidence.max(0.95);
    }

    // NSPack sections
    if section_names.iter().any(|s| *s == ".nsp0" || *s == ".nsp1" || *s == ".nsp2") {
        packers.insert(PackerType::NsPack);
        signatures.push("NSPack section name".to_string());
        confidence = confidence.max(0.95);
    }

    // === Heuristic Detection ===
    // No section headers at all (stripped by packer)
    if section_names.is_empty() && data.len() > 1024 {
        // Check for ELF or PE magic to confirm it's a binary
        let is_elf = data.starts_with(&[0x7F, 0x45, 0x4C, 0x46]);
        let is_pe = data.starts_with(&[0x4D, 0x5A]); // MZ
        if is_elf || is_pe {
            // Only flag as packed if we don't have any other indicators
            if packers.is_empty() {
                packers.insert(PackerType::Unknown("stripped sections".to_string()));
                signatures.push("No section headers (stripped)".to_string());
                confidence = confidence.max(0.5);
            }
        }
    }

    PackerInfo::detected(packers.into_iter().collect(), confidence, signatures)
}

/// Check if data contains a signature (case-sensitive)
fn has_signature(data: &[u8], signature: &[u8]) -> bool {
    data.windows(signature.len()).any(|w| w == signature)
}

/// Additional heuristics for detecting packed ELF binaries
pub fn detect_packed_elf_heuristics(
    has_section_headers: bool,
    section_count: usize,
    _segment_count: usize,
) -> Option<String> {
    // ELF binaries stripped of section headers are often packed
    // Normal ELF files have section headers even if stripped of symbols
    if !has_section_headers || section_count == 0 {
        return Some("Binary has no section headers (common in packed binaries)".to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upx_info_string_detection() {
        let data = b"random data $Info: This file is packed with the UPX more data";
        let info = detect_packer(data, &[]);
        assert!(info.is_packed);
        assert!(info.packers.contains(&PackerType::Upx));
    }

    #[test]
    fn test_upx_section_detection() {
        let data = b"random data without UPX magic";
        let sections = vec!["UPX0", "UPX1", ".text"];
        let info = detect_packer(data, &sections);
        assert!(info.is_packed);
        assert!(info.packers.contains(&PackerType::Upx));
    }

    #[test]
    fn test_upx_trailer_detection() {
        // Simulate a binary with UPX trailer magic at the end
        let mut data = vec![0u8; 100];
        data.extend_from_slice(b"UPX!");
        let info = detect_packer(&data, &[]);
        assert!(info.is_packed);
        assert!(info.packers.contains(&PackerType::Upx));
    }

    #[test]
    fn test_no_packer() {
        let data = b"normal binary data without packer signatures";
        let sections = vec![".text", ".data", ".rodata"];
        let info = detect_packer(data, &sections);
        assert!(!info.is_packed);
        assert!(info.packers.is_empty());
    }

    #[test]
    fn test_upx_magic_in_code_no_false_positive() {
        // If "UPX!" appears in the middle of the binary (e.g., in code),
        // it should NOT trigger detection unless accompanied by other indicators
        let mut data = vec![0u8; 50];
        data.extend_from_slice(b"UPX!");  // In the middle
        data.extend_from_slice(&vec![0u8; 50]);
        let sections = vec![".text", ".data"];  // Normal sections
        let info = detect_packer(&data, &sections);
        // This should NOT detect as packed because UPX! is not in the trailer
        // and there are no UPX section names
        assert!(!info.is_packed || !info.packers.contains(&PackerType::Upx)
            || info.confidence < 0.9);
    }

    #[test]
    fn test_vmprotect_detection() {
        let data = b"some data VMProtect other data";
        let info = detect_packer(data, &[".vmp0", ".vmp1"]);
        assert!(info.is_packed);
        assert!(info.packers.contains(&PackerType::VMProtect));
    }

    #[test]
    fn test_packer_name() {
        assert_eq!(PackerType::Upx.name(), "UPX");
        assert_eq!(PackerType::VMProtect.name(), "VMProtect");
        assert_eq!(
            PackerType::Unknown("custom".to_string()).name(),
            "custom"
        );
    }
}
