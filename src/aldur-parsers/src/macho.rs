//! Mach-O binary parser
//!
//! Parses macOS/iOS Mach-O binaries including:
//! - Mach-O headers and load commands
//! - Fat (universal) binaries
//! - Segment information
//! - Security flags
//! - Symbol table access

use aldur_core::{AldurError, Binary, BinaryFormat, BinaryType, Result};
use goblin::mach::{Mach, MachO as GoblinMachO};
use std::path::{Path, PathBuf};

use crate::memory::{BinaryData, MemoryBudget};

/// Mach-O file types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachOType {
    Object,
    Execute,
    Dylib,
    Bundle,
    Dylinker,
    Core,
    Preload,
    Dsym,
    Unknown(u32),
}

impl From<u32> for MachOType {
    fn from(t: u32) -> Self {
        match t {
            1 => MachOType::Object,
            2 => MachOType::Execute,
            6 => MachOType::Dylib,
            8 => MachOType::Bundle,
            7 => MachOType::Dylinker,
            4 => MachOType::Core,
            5 => MachOType::Preload,
            10 => MachOType::Dsym,
            other => MachOType::Unknown(other),
        }
    }
}

/// Mach-O header flags
pub mod header_flags {
    /// The object file has no undefined references
    pub const MH_NOUNDEFS: u32 = 0x1;
    /// Two-level namespace bindings (symbols bound to defining library)
    pub const MH_TWOLEVEL: u32 = 0x80;
    /// Force flat namespace bindings
    pub const MH_FORCE_FLAT: u32 = 0x100;
    /// The object allows stack execution
    pub const MH_ALLOW_STACK_EXECUTION: u32 = 0x20000;
    /// The object file is position independent executable
    pub const MH_PIE: u32 = 0x200000;
    /// The object has no heap execution allowed
    pub const MH_NO_HEAP_EXECUTION: u32 = 0x1000000;
    /// App extension safe
    pub const MH_APP_EXTENSION_SAFE: u32 = 0x02000000;
}

/// CPU types
pub mod cpu_type {
    pub const CPU_TYPE_I386: i32 = 7;
    pub const CPU_TYPE_X86_64: i32 = 7 | 0x01000000;
    pub const CPU_TYPE_ARM: i32 = 12;
    pub const CPU_TYPE_ARM64: i32 = 12 | 0x01000000;
}

/// Load command types
pub mod load_command {
    pub const LC_LOAD_WEAK_DYLIB: u32 = 0x18 | 0x80000000;
    pub const LC_RPATH: u32 = 0x1c | 0x80000000;
    pub const LC_CODE_SIGNATURE: u32 = 0x1d;
    pub const LC_ENCRYPTION_INFO: u32 = 0x21;
    pub const LC_ENCRYPTION_INFO_64: u32 = 0x2c;
    pub const LC_BUILD_VERSION: u32 = 0x32;
}

/// Segment protection flags
pub mod segment_flags {
    /// Segment is readable
    pub const VM_PROT_READ: u32 = 0x01;
    /// Segment is writable
    pub const VM_PROT_WRITE: u32 = 0x02;
    /// Segment is executable
    pub const VM_PROT_EXECUTE: u32 = 0x04;
}

/// Code signature flags (from codesign.h)
pub mod codesign_flags {
    /// Hardened runtime enabled
    pub const CS_RUNTIME: u32 = 0x00010000;
    /// Library validation enabled
    pub const CS_LIBRARY_VALIDATION: u32 = 0x00002000;
    /// Restrict segment present
    pub const CS_RESTRICT: u32 = 0x00000800;
}

/// Segment information from Mach-O
#[derive(Debug, Clone)]
pub struct MachOSegment {
    /// Segment name
    pub name: String,
    /// Virtual memory address
    pub vmaddr: u64,
    /// Virtual memory size
    pub vmsize: u64,
    /// Initial protection flags
    pub initprot: u32,
    /// Maximum protection flags
    pub maxprot: u32,
}

/// Single Mach-O architecture (for fat binaries)
#[derive(Debug, Clone)]
pub struct MachOArch {
    /// CPU type
    pub cpu_type: i32,
    /// CPU subtype
    pub cpu_subtype: i32,
    /// File type
    pub file_type: MachOType,
    /// Header flags
    pub flags: u32,
    /// Is 64-bit
    pub is_64_bit: bool,
}

impl MachOArch {
    /// Check if this is a PIE
    pub fn is_pie(&self) -> bool {
        self.flags & header_flags::MH_PIE != 0
    }

    /// Check if stack execution is allowed
    pub fn allows_stack_execution(&self) -> bool {
        self.flags & header_flags::MH_ALLOW_STACK_EXECUTION != 0
    }

    /// Check if heap execution is disallowed
    pub fn disallows_heap_execution(&self) -> bool {
        self.flags & header_flags::MH_NO_HEAP_EXECUTION != 0
    }

    /// Check if two-level namespace is enabled
    pub fn has_two_level_namespace(&self) -> bool {
        self.flags & header_flags::MH_TWOLEVEL != 0
    }

    /// Check if this is an ARM64 architecture
    pub fn is_arm64(&self) -> bool {
        self.cpu_type == cpu_type::CPU_TYPE_ARM64
    }
}

/// Minimum OS version information
#[derive(Debug, Clone, Default)]
pub struct MinOSVersion {
    /// Platform (macOS, iOS, tvOS, watchOS)
    pub platform: String,
    /// Major version
    pub major: u32,
    /// Minor version
    pub minor: u32,
    /// Patch version
    pub patch: u32,
}

impl MinOSVersion {
    /// Check if version is at least the specified version
    pub fn is_at_least(&self, major: u32, minor: u32, patch: u32) -> bool {
        (self.major, self.minor, self.patch) >= (major, minor, patch)
    }

    /// Format as string (e.g., "10.15.0")
    pub fn to_version_string(&self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Mach-O binary representation
pub struct MachOBinary {
    /// Path to the binary
    path: PathBuf,
    /// Raw file data (heap-allocated or memory-mapped)
    data: BinaryData,
    /// Whether the binary is valid
    valid: bool,
    /// Load error if any
    load_error: Option<String>,
    /// Whether this is a fat (universal) binary
    pub is_fat: bool,
    /// Architectures in this binary
    pub architectures: Vec<MachOArch>,
    /// Whether the binary has weak dylib load commands
    pub has_weak_dylib: bool,
    /// Weak dylib names
    pub weak_dylibs: Vec<String>,
    /// RPATH entries
    pub rpaths: Vec<String>,
    /// Has code signature
    pub has_code_signature: bool,
    /// Is encrypted (App Store encryption)
    pub is_encrypted: bool,
    /// Segments from the binary
    pub segments: Vec<MachOSegment>,
    /// Hardened runtime is enabled (from code signature)
    pub has_hardened_runtime: bool,
    /// Library validation is enabled
    pub has_library_validation: bool,
    /// Minimum OS version
    pub min_os_version: Option<MinOSVersion>,
    /// Has __RESTRICT segment
    pub has_restrict_segment: bool,
    /// Packer detection information
    pub packer_info: crate::packer::PackerInfo,
}

impl MachOBinary {
    /// Load a Mach-O binary from a file using the default memory budget
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        Self::load_with_budget(path, &MemoryBudget::default())
    }

    /// Load a Mach-O binary from a file with a custom memory budget
    pub fn load_with_budget(path: impl AsRef<Path>, budget: &MemoryBudget) -> Result<Self> {
        let path = path.as_ref();
        let data = budget
            .load(path)
            .map_err(|e| AldurError::binary_load(path.display().to_string(), e.to_string()))?;
        Self::parse(path.to_path_buf(), data)
    }

    /// Load a Mach-O binary from raw bytes (e.g., extracted from an archive)
    pub fn load_from_bytes(path: PathBuf, bytes: Vec<u8>) -> Result<Self> {
        Self::parse(path, BinaryData::Owned(bytes))
    }

    fn parse(path: PathBuf, data: BinaryData) -> Result<Self> {
        let mach = Mach::parse(&data).map_err(|e| AldurError::MachOParseError(e.to_string()))?;

        // Extract architecture info and load command info
        let (
            is_fat,
            architectures,
            has_weak_dylib,
            weak_dylibs,
            rpaths,
            has_code_signature,
            is_encrypted,
            segments,
        ) = match &mach {
            Mach::Binary(macho) => {
                let (weak, weak_names, rpath_list, code_sig, encrypted) =
                    Self::extract_load_commands(macho);
                let segs = Self::extract_segments(macho);
                (
                    false,
                    vec![Self::extract_arch(macho)],
                    weak,
                    weak_names,
                    rpath_list,
                    code_sig,
                    encrypted,
                    segs,
                )
            }
            Mach::Fat(fat) => {
                let mut archs = Vec::new();
                let mut all_weak_dylibs = Vec::new();
                let mut all_rpaths = Vec::new();
                let mut all_segments = Vec::new();
                let mut any_weak = false;
                let mut any_code_sig = false;
                let mut any_encrypted = false;
                for i in 0..fat.narches {
                    if let Ok(goblin::mach::SingleArch::MachO(ref macho)) = fat.get(i) {
                        archs.push(Self::extract_arch(macho));
                        let (weak, weak_names, rpath_list, code_sig, encrypted) =
                            Self::extract_load_commands(macho);
                        any_weak |= weak;
                        any_code_sig |= code_sig;
                        any_encrypted |= encrypted;
                        all_weak_dylibs.extend(weak_names);
                        all_rpaths.extend(rpath_list);
                        all_segments.extend(Self::extract_segments(macho));
                    }
                }
                (
                    true,
                    archs,
                    any_weak,
                    all_weak_dylibs,
                    all_rpaths,
                    any_code_sig,
                    any_encrypted,
                    all_segments,
                )
            }
        };

        // Try to detect hardened runtime and library validation from code signature
        // This requires parsing the code signature blob, which is complex.
        // For now, we'll set these to false and detect via other means.
        let has_hardened_runtime = false;
        let has_library_validation = false;

        // Check for __RESTRICT segment
        let has_restrict_segment = segments.iter().any(|s| s.name == "__RESTRICT");

        // Extract minimum OS version from load commands
        let min_os_version = Self::extract_min_os_version(&mach);

        // Detect if the binary is packed
        let segment_names: Vec<&str> = segments.iter().map(|s| s.name.as_str()).collect();
        let packer_info = crate::packer::detect_packer(&data, &segment_names);

        let binary = MachOBinary {
            path,
            valid: true,
            load_error: None,
            is_fat,
            architectures,
            has_weak_dylib,
            weak_dylibs,
            rpaths,
            has_code_signature,
            is_encrypted,
            segments,
            has_hardened_runtime,
            has_library_validation,
            min_os_version,
            has_restrict_segment,
            packer_info,
            data,
        };

        Ok(binary)
    }

    fn extract_segments(macho: &GoblinMachO) -> Vec<MachOSegment> {
        let mut segments = Vec::new();
        for seg in &macho.segments {
            let name = seg.name().unwrap_or("").to_string();
            segments.push(MachOSegment {
                name,
                vmaddr: seg.vmaddr,
                vmsize: seg.vmsize,
                initprot: seg.initprot,
                maxprot: seg.maxprot,
            });
        }
        segments
    }

    fn extract_load_commands(macho: &GoblinMachO) -> (bool, Vec<String>, Vec<String>, bool, bool) {
        use goblin::mach::load_command::CommandVariant;

        let mut has_weak_dylib = false;
        let mut weak_dylibs: Vec<String> = Vec::new();
        let mut rpaths: Vec<String> = Vec::new();
        let mut has_code_signature = false;
        let mut is_encrypted = false;

        for lc in &macho.load_commands {
            match lc.command {
                CommandVariant::LoadWeakDylib(ref _dylib) => {
                    has_weak_dylib = true;
                    // Note: The name is an offset - we'll extract from libs instead
                }
                CommandVariant::Rpath(ref _rpath_cmd) => {
                    // Note: The path is an offset - rpaths are tracked separately by goblin
                }
                CommandVariant::CodeSignature(_) => {
                    has_code_signature = true;
                }
                CommandVariant::EncryptionInfo32(_) | CommandVariant::EncryptionInfo64(_) => {
                    is_encrypted = true;
                }
                _ => {}
            }
        }

        // Get weak dylib names from goblin's parsed libs
        // goblin parses the string table and provides library names directly
        for lib in &macho.libs {
            if !lib.is_empty() && has_weak_dylib {
                // We can't easily distinguish weak from regular here,
                // so just store all when has_weak_dylib is true
                weak_dylibs.push(lib.to_string());
            }
        }

        // Get rpaths from goblin's parsed rpaths field
        for rpath in &macho.rpaths {
            rpaths.push(rpath.to_string());
        }

        (
            has_weak_dylib,
            weak_dylibs,
            rpaths,
            has_code_signature,
            is_encrypted,
        )
    }

    fn extract_arch(macho: &GoblinMachO) -> MachOArch {
        let is_64_bit = macho.header.cputype & 0x01000000 != 0;
        MachOArch {
            cpu_type: macho.header.cputype as i32,
            cpu_subtype: macho.header.cpusubtype as i32,
            file_type: MachOType::from(macho.header.filetype),
            flags: macho.header.flags,
            is_64_bit,
        }
    }

    fn extract_min_os_version(mach: &Mach) -> Option<MinOSVersion> {
        match mach {
            Mach::Binary(macho) => Self::extract_min_os_version_from_macho(macho),
            Mach::Fat(fat) => {
                // Try to get from the first architecture
                for i in 0..fat.narches {
                    if let Ok(goblin::mach::SingleArch::MachO(ref macho)) = fat.get(i) {
                        if let Some(ver) = Self::extract_min_os_version_from_macho(macho) {
                            return Some(ver);
                        }
                    }
                }
                None
            }
        }
    }

    fn extract_min_os_version_from_macho(macho: &GoblinMachO) -> Option<MinOSVersion> {
        use goblin::mach::load_command::CommandVariant;

        for lc in &macho.load_commands {
            match &lc.command {
                CommandVariant::VersionMinMacosx(cmd) => {
                    let version = cmd.version;
                    return Some(MinOSVersion {
                        platform: "macOS".to_string(),
                        major: (version >> 16) & 0xFFFF,
                        minor: (version >> 8) & 0xFF,
                        patch: version & 0xFF,
                    });
                }
                CommandVariant::VersionMinIphoneos(cmd) => {
                    let version = cmd.version;
                    return Some(MinOSVersion {
                        platform: "iOS".to_string(),
                        major: (version >> 16) & 0xFFFF,
                        minor: (version >> 8) & 0xFF,
                        patch: version & 0xFF,
                    });
                }
                CommandVariant::BuildVersion(cmd) => {
                    let version = cmd.minos;
                    let platform = match cmd.platform {
                        1 => "macOS",
                        2 => "iOS",
                        3 => "tvOS",
                        4 => "watchOS",
                        5 => "bridgeOS",
                        6 => "macCatalyst",
                        7 => "iOSSimulator",
                        8 => "tvOSSimulator",
                        9 => "watchOSSimulator",
                        _ => "Unknown",
                    };
                    return Some(MinOSVersion {
                        platform: platform.to_string(),
                        major: (version >> 16) & 0xFFFF,
                        minor: (version >> 8) & 0xFF,
                        patch: version & 0xFF,
                    });
                }
                _ => {}
            }
        }
        None
    }

    /// Get the primary architecture (first one for fat binaries)
    pub fn primary_arch(&self) -> Option<&MachOArch> {
        self.architectures.first()
    }

    /// Check if this is a fat (universal) binary
    pub fn is_universal(&self) -> bool {
        self.is_fat
    }

    /// Check if all architectures are PIE
    pub fn is_pie(&self) -> bool {
        self.architectures.iter().all(|a| a.is_pie())
    }

    /// Check if any architecture allows stack execution
    pub fn allows_stack_execution(&self) -> bool {
        self.architectures
            .iter()
            .any(|a| a.allows_stack_execution())
    }

    /// Get the file type of the primary architecture
    pub fn file_type(&self) -> Option<MachOType> {
        self.primary_arch().map(|a| a.file_type)
    }

    /// Check if the binary has any of the specified symbols
    pub fn has_any_symbol(&self, symbols: &[&str]) -> bool {
        // Re-parse the Mach-O to get symbols
        if let Ok(mach) = Mach::parse(&self.data) {
            match mach {
                Mach::Binary(macho) => {
                    return Self::macho_has_symbols(&macho, symbols);
                }
                Mach::Fat(fat) => {
                    // Check all architectures in fat binary
                    for i in 0..fat.narches {
                        if let Ok(goblin::mach::SingleArch::MachO(ref macho)) = fat.get(i) {
                            if Self::macho_has_symbols(macho, symbols) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    fn macho_has_symbols(macho: &GoblinMachO, symbols: &[&str]) -> bool {
        if let Some(ref syms) = macho.symbols {
            for (name, _) in syms.iter().flatten() {
                // Mach-O symbols often have a leading underscore
                let name_trimmed = name.trim_start_matches('_');
                if symbols.iter().any(|s| {
                    let s_trimmed = s.trim_start_matches('_');
                    name.contains(s) || name_trimmed.contains(s_trimmed)
                }) {
                    return true;
                }
            }
        }
        false
    }

    fn macho_has_symbols_exact(macho: &GoblinMachO, symbols: &[&str]) -> bool {
        if let Some(ref syms) = macho.symbols {
            for (name, _) in syms.iter().flatten() {
                // Mach-O symbols often have a leading underscore
                let name_trimmed = name.trim_start_matches('_');
                if symbols.iter().any(|s| {
                    let s_trimmed = s.trim_start_matches('_');
                    name == *s || name_trimmed == s_trimmed
                }) {
                    return true;
                }
            }
        }
        false
    }

    /// Check if the binary has any of the specified symbols (exact match)
    pub fn has_any_symbol_exact(&self, symbols: &[&str]) -> bool {
        if let Ok(mach) = Mach::parse(&self.data) {
            match mach {
                Mach::Binary(macho) => {
                    return Self::macho_has_symbols_exact(&macho, symbols);
                }
                Mach::Fat(fat) => {
                    for i in 0..fat.narches {
                        if let Ok(goblin::mach::SingleArch::MachO(ref macho)) = fat.get(i) {
                            if Self::macho_has_symbols_exact(macho, symbols) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Check if the binary has a specific symbol (exact match)
    pub fn has_symbol_exact(&self, symbol: &str) -> bool {
        self.has_any_symbol_exact(&[symbol])
    }

    /// Check if the binary has a specific symbol
    pub fn has_symbol(&self, symbol: &str) -> bool {
        self.has_any_symbol(&[symbol])
    }

    /// Get all symbol names from the binary
    pub fn get_all_symbol_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        if let Ok(mach) = Mach::parse(&self.data) {
            match mach {
                Mach::Binary(macho) => {
                    Self::collect_symbol_names(&macho, &mut names);
                }
                Mach::Fat(fat) => {
                    for i in 0..fat.narches {
                        if let Ok(goblin::mach::SingleArch::MachO(ref macho)) = fat.get(i) {
                            Self::collect_symbol_names(macho, &mut names);
                        }
                    }
                }
            }
        }
        names
    }

    fn collect_symbol_names(macho: &GoblinMachO, names: &mut Vec<String>) {
        if let Some(ref syms) = macho.symbols {
            for (name, _) in syms.iter().flatten() {
                if !name.is_empty() {
                    names.push(name.to_string());
                }
            }
        }
    }

    /// Check if all architectures disallow heap execution
    pub fn disallows_heap_execution(&self) -> bool {
        // For executables, check if MH_NO_HEAP_EXECUTION is set
        // Note: This flag may not be set on all binaries, so we check
        // if it's set on any architecture
        self.architectures
            .iter()
            .all(|a| a.disallows_heap_execution())
    }

    /// Check if any architecture is ARM64 (Apple Silicon)
    pub fn has_arm64(&self) -> bool {
        self.architectures.iter().any(|a| a.is_arm64())
    }

    /// Check if all architectures use two-level namespace
    pub fn has_two_level_namespace(&self) -> bool {
        self.architectures
            .iter()
            .all(|a| a.has_two_level_namespace())
    }

    /// Check if this is a shared library (dylib or bundle)
    pub fn is_shared_library(&self) -> bool {
        matches!(
            self.file_type(),
            Some(MachOType::Dylib) | Some(MachOType::Bundle)
        )
    }

    /// Check if this is an executable
    pub fn is_executable(&self) -> bool {
        matches!(self.file_type(), Some(MachOType::Execute))
    }

    /// Get the raw data for DWARF parsing
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get a segment by name
    pub fn get_segment(&self, name: &str) -> Option<&MachOSegment> {
        self.segments.iter().find(|s| s.name == name)
    }

    /// Check if __DATA segment is executable (should not be)
    pub fn has_executable_data_segment(&self) -> bool {
        self.segments.iter().any(|s| {
            (s.name == "__DATA" || s.name == "__DATA_CONST" || s.name == "__DATA_DIRTY")
                && (s.initprot & segment_flags::VM_PROT_EXECUTE != 0)
        })
    }

    /// Check if __TEXT segment is writable (should not be)
    pub fn has_writable_text_segment(&self) -> bool {
        self.segments
            .iter()
            .any(|s| s.name == "__TEXT" && (s.initprot & segment_flags::VM_PROT_WRITE != 0))
    }

    /// Get segments with both write and execute permissions (W^X violation)
    pub fn get_wxorx_violating_segments(&self) -> Vec<&MachOSegment> {
        self.segments
            .iter()
            .filter(|s| {
                let is_write = s.initprot & segment_flags::VM_PROT_WRITE != 0;
                let is_exec = s.initprot & segment_flags::VM_PROT_EXECUTE != 0;
                is_write && is_exec
            })
            .collect()
    }

    /// Check if there are any W^X (write XOR execute) violations
    pub fn has_wxorx_violation(&self) -> bool {
        !self.get_wxorx_violating_segments().is_empty()
    }

    /// Check if this binary appears to be packed
    pub fn is_packed(&self) -> bool {
        self.packer_info.is_packed
    }

    /// Get packer information
    pub fn packer_info(&self) -> &crate::packer::PackerInfo {
        &self.packer_info
    }
}

impl Binary for MachOBinary {
    fn path(&self) -> &Path {
        &self.path
    }

    fn format(&self) -> BinaryFormat {
        BinaryFormat::MachO
    }

    fn binary_type(&self) -> BinaryType {
        match self.file_type() {
            Some(MachOType::Execute) => BinaryType::Executable,
            Some(MachOType::Dylib) | Some(MachOType::Bundle) => BinaryType::DynamicLibrary,
            Some(MachOType::Object) => BinaryType::Object,
            Some(MachOType::Core) => BinaryType::Core,
            _ => BinaryType::Unknown,
        }
    }

    fn is_64_bit(&self) -> bool {
        self.primary_arch().map(|a| a.is_64_bit).unwrap_or(false)
    }

    fn is_valid(&self) -> bool {
        self.valid
    }

    fn load_error(&self) -> Option<&str> {
        self.load_error.as_deref()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macho_type_conversion() {
        assert_eq!(MachOType::from(1), MachOType::Object);
        assert_eq!(MachOType::from(2), MachOType::Execute);
        assert_eq!(MachOType::from(6), MachOType::Dylib);
        assert_eq!(MachOType::from(8), MachOType::Bundle);
        assert_eq!(MachOType::from(7), MachOType::Dylinker);
        assert_eq!(MachOType::from(4), MachOType::Core);
        assert_eq!(MachOType::from(5), MachOType::Preload);
        assert_eq!(MachOType::from(10), MachOType::Dsym);
        assert_eq!(MachOType::from(999), MachOType::Unknown(999));
    }

    #[test]
    fn test_header_flag_values() {
        // Verify header flag values match Apple's definitions
        assert_eq!(header_flags::MH_NOUNDEFS, 0x1);
        assert_eq!(header_flags::MH_TWOLEVEL, 0x80);
        assert_eq!(header_flags::MH_FORCE_FLAT, 0x100);
        assert_eq!(header_flags::MH_ALLOW_STACK_EXECUTION, 0x20000);
        assert_eq!(header_flags::MH_PIE, 0x200000);
        assert_eq!(header_flags::MH_NO_HEAP_EXECUTION, 0x1000000);
        assert_eq!(header_flags::MH_APP_EXTENSION_SAFE, 0x02000000);
    }

    #[test]
    fn test_cpu_type_values() {
        assert_eq!(cpu_type::CPU_TYPE_I386, 7);
        assert_eq!(cpu_type::CPU_TYPE_X86_64, 7 | 0x01000000);
        assert_eq!(cpu_type::CPU_TYPE_ARM, 12);
        assert_eq!(cpu_type::CPU_TYPE_ARM64, 12 | 0x01000000);
    }

    #[test]
    fn test_macho_arch_is_pie() {
        let arch_pie = MachOArch {
            cpu_type: cpu_type::CPU_TYPE_X86_64,
            cpu_subtype: 0,
            file_type: MachOType::Execute,
            flags: header_flags::MH_PIE | header_flags::MH_TWOLEVEL,
            is_64_bit: true,
        };
        assert!(arch_pie.is_pie());

        let arch_no_pie = MachOArch {
            cpu_type: cpu_type::CPU_TYPE_X86_64,
            cpu_subtype: 0,
            file_type: MachOType::Execute,
            flags: header_flags::MH_TWOLEVEL,
            is_64_bit: true,
        };
        assert!(!arch_no_pie.is_pie());
    }

    #[test]
    fn test_macho_arch_stack_execution() {
        let arch_exec_stack = MachOArch {
            cpu_type: cpu_type::CPU_TYPE_X86_64,
            cpu_subtype: 0,
            file_type: MachOType::Execute,
            flags: header_flags::MH_ALLOW_STACK_EXECUTION,
            is_64_bit: true,
        };
        assert!(arch_exec_stack.allows_stack_execution());

        let arch_no_exec_stack = MachOArch {
            cpu_type: cpu_type::CPU_TYPE_X86_64,
            cpu_subtype: 0,
            file_type: MachOType::Execute,
            flags: header_flags::MH_PIE,
            is_64_bit: true,
        };
        assert!(!arch_no_exec_stack.allows_stack_execution());
    }

    #[test]
    fn test_macho_arch_heap_execution() {
        let arch_no_heap_exec = MachOArch {
            cpu_type: cpu_type::CPU_TYPE_X86_64,
            cpu_subtype: 0,
            file_type: MachOType::Execute,
            flags: header_flags::MH_NO_HEAP_EXECUTION,
            is_64_bit: true,
        };
        assert!(arch_no_heap_exec.disallows_heap_execution());

        let arch_heap_exec = MachOArch {
            cpu_type: cpu_type::CPU_TYPE_X86_64,
            cpu_subtype: 0,
            file_type: MachOType::Execute,
            flags: 0,
            is_64_bit: true,
        };
        assert!(!arch_heap_exec.disallows_heap_execution());
    }

    #[test]
    fn test_macho_arch_two_level_namespace() {
        let arch_twolevel = MachOArch {
            cpu_type: cpu_type::CPU_TYPE_X86_64,
            cpu_subtype: 0,
            file_type: MachOType::Execute,
            flags: header_flags::MH_TWOLEVEL,
            is_64_bit: true,
        };
        assert!(arch_twolevel.has_two_level_namespace());

        let arch_flat = MachOArch {
            cpu_type: cpu_type::CPU_TYPE_X86_64,
            cpu_subtype: 0,
            file_type: MachOType::Execute,
            flags: header_flags::MH_FORCE_FLAT,
            is_64_bit: true,
        };
        assert!(!arch_flat.has_two_level_namespace());
    }

    #[test]
    fn test_macho_arch_is_arm64() {
        let arch_arm64 = MachOArch {
            cpu_type: cpu_type::CPU_TYPE_ARM64,
            cpu_subtype: 0,
            file_type: MachOType::Execute,
            flags: 0,
            is_64_bit: true,
        };
        assert!(arch_arm64.is_arm64());

        let arch_x86_64 = MachOArch {
            cpu_type: cpu_type::CPU_TYPE_X86_64,
            cpu_subtype: 0,
            file_type: MachOType::Execute,
            flags: 0,
            is_64_bit: true,
        };
        assert!(!arch_x86_64.is_arm64());

        let arch_arm32 = MachOArch {
            cpu_type: cpu_type::CPU_TYPE_ARM,
            cpu_subtype: 0,
            file_type: MachOType::Execute,
            flags: 0,
            is_64_bit: false,
        };
        assert!(!arch_arm32.is_arm64());
    }

    #[test]
    fn test_segment_flags() {
        assert_eq!(segment_flags::VM_PROT_READ, 0x01);
        assert_eq!(segment_flags::VM_PROT_WRITE, 0x02);
        assert_eq!(segment_flags::VM_PROT_EXECUTE, 0x04);
    }

    #[test]
    fn test_macho_segment_struct() {
        let segment = MachOSegment {
            name: "__TEXT".to_string(),
            vmaddr: 0x100000000,
            vmsize: 0x4000,
            initprot: segment_flags::VM_PROT_READ | segment_flags::VM_PROT_EXECUTE,
            maxprot: segment_flags::VM_PROT_READ | segment_flags::VM_PROT_EXECUTE,
        };

        assert_eq!(segment.name, "__TEXT");
        assert!(segment.initprot & segment_flags::VM_PROT_EXECUTE != 0);
        assert!(segment.initprot & segment_flags::VM_PROT_WRITE == 0);
    }
}
