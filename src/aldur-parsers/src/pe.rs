//! PE (Portable Executable) binary parser
//!
//! Parses Windows PE binaries including:
//! - PE headers and optional headers
//! - Section tables
//! - Import/export tables
//! - Load configuration directory (for CFG, CET, etc.)
//! - Debug directories

use aldur_core::{AldurError, Binary, BinaryFormat, BinaryType, Result};
use goblin::pe::PE;
use std::path::{Path, PathBuf};

use crate::memory::{BinaryData, MemoryBudget};

/// DLL characteristics flags
pub mod dll_characteristics {
    /// Image can handle a high entropy 64-bit virtual address space
    pub const HIGH_ENTROPY_VA: u16 = 0x0020;
    /// DLL can be relocated at load time
    pub const DYNAMIC_BASE: u16 = 0x0040;
    /// Code Integrity checks are enforced
    pub const FORCE_INTEGRITY: u16 = 0x0080;
    /// Image is NX compatible
    pub const NX_COMPAT: u16 = 0x0100;
    /// Isolation aware, but do not isolate the image
    pub const NO_ISOLATION: u16 = 0x0200;
    /// Does not use structured exception handling (SEH)
    pub const NO_SEH: u16 = 0x0400;
    /// Do not bind the image
    pub const NO_BIND: u16 = 0x0800;
    /// Image should execute in an AppContainer
    pub const APPCONTAINER: u16 = 0x1000;
    /// A WDM driver
    pub const WDM_DRIVER: u16 = 0x2000;
    /// Image supports Control Flow Guard
    pub const GUARD_CF: u16 = 0x4000;
    /// Terminal Server aware
    pub const TERMINAL_SERVER_AWARE: u16 = 0x8000;
}

/// Image file characteristics
pub mod file_characteristics {
    /// Relocation info stripped from file
    pub const RELOCS_STRIPPED: u16 = 0x0001;
    /// File is executable
    pub const EXECUTABLE_IMAGE: u16 = 0x0002;
    /// COFF line numbers stripped
    pub const LINE_NUMS_STRIPPED: u16 = 0x0004;
    /// COFF symbol table entries stripped
    pub const LOCAL_SYMS_STRIPPED: u16 = 0x0008;
    /// Aggressive trim working set (obsolete)
    pub const AGGRESSIVE_WS_TRIM: u16 = 0x0010;
    /// Application can handle >2GB addresses
    pub const LARGE_ADDRESS_AWARE: u16 = 0x0020;
    /// Machine word bytes reversed (obsolete)
    pub const BYTES_REVERSED_LO: u16 = 0x0080;
    /// 32-bit word machine
    pub const MACHINE_32BIT: u16 = 0x0100;
    /// Debug info stripped
    pub const DEBUG_STRIPPED: u16 = 0x0200;
    /// If image on removable media, copy and run from swap file
    pub const REMOVABLE_RUN_FROM_SWAP: u16 = 0x0400;
    /// If image on network media, copy and run from swap file
    pub const NET_RUN_FROM_SWAP: u16 = 0x0800;
    /// System file
    pub const SYSTEM: u16 = 0x1000;
    /// File is a DLL
    pub const DLL: u16 = 0x2000;
    /// File should only be run on a UP machine
    pub const UP_SYSTEM_ONLY: u16 = 0x4000;
    /// Machine word bytes reversed (obsolete)
    pub const BYTES_REVERSED_HI: u16 = 0x8000;
}

/// Guard flags for Control Flow Guard
pub mod guard_flags {
    /// Module performs control flow integrity checks using system-supplied support
    pub const CF_INSTRUMENTED: u32 = 0x0100;
    /// Module performs control flow and write integrity checks
    pub const CFW_INSTRUMENTED: u32 = 0x0200;
    /// Module contains valid control flow target metadata
    pub const CF_FUNCTION_TABLE_PRESENT: u32 = 0x0400;
    /// Module does not make use of the /GS security feature
    pub const SECURITY_COOKIE_UNUSED: u32 = 0x0800;
    /// Module supports read-only delay load imports
    pub const PROTECT_DELAYLOAD_IAT: u32 = 0x1000;
    /// Delayload import table in its own .didat section
    pub const DELAYLOAD_IAT_IN_ITS_OWN_SECTION: u32 = 0x2000;
    /// Module contains suppressed export information
    pub const CF_EXPORT_SUPPRESSION_INFO_PRESENT: u32 = 0x4000;
    /// Module enables suppression of exports
    pub const CF_ENABLE_EXPORT_SUPPRESSION: u32 = 0x8000;
    /// Module contains longjmp target information
    pub const CF_LONGJUMP_TABLE_PRESENT: u32 = 0x10000;
    /// Mask for CF checks
    pub const CF_CHECKS: u32 = CF_INSTRUMENTED | CF_FUNCTION_TABLE_PRESENT;
    /// CastGuard is enabled (/guard:cast)
    pub const EH_CONTINUATION_TABLE_PRESENT: u32 = 0x00400000;
    /// Retpoline is enabled
    pub const RETPOLINE_PRESENT: u32 = 0x00100000;
    /// Return Flow Guard is instrumented
    pub const RF_INSTRUMENTED: u32 = 0x0002_0000;
    /// Return Flow Guard is enabled
    pub const RF_ENABLE: u32 = 0x0004_0000;
    /// Return Flow Guard strict mode
    pub const RF_STRICT: u32 = 0x0008_0000;
}

/// Section characteristics
pub mod section_characteristics {
    /// Section contains executable code
    pub const CNT_CODE: u32 = 0x0000_0020;
    /// Section contains initialized data
    pub const CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
    /// Section contains uninitialized data
    pub const CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
    /// Section can be executed as code
    pub const MEM_EXECUTE: u32 = 0x2000_0000;
    /// Section can be read
    pub const MEM_READ: u32 = 0x4000_0000;
    /// Section can be written to
    pub const MEM_WRITE: u32 = 0x8000_0000;
    /// Section can be shared in memory
    pub const MEM_SHARED: u32 = 0x1000_0000;
}

/// Section information
#[derive(Debug, Clone)]
pub struct SectionInfo {
    /// Section name
    pub name: String,
    /// Virtual address
    pub virtual_address: u32,
    /// Virtual size
    pub virtual_size: u32,
    /// Raw data size
    pub raw_data_size: u32,
    /// Section characteristics
    pub characteristics: u32,
}

impl SectionInfo {
    /// Check if section is executable
    pub fn is_executable(&self) -> bool {
        self.characteristics & section_characteristics::MEM_EXECUTE != 0
    }

    /// Check if section is writable
    pub fn is_writable(&self) -> bool {
        self.characteristics & section_characteristics::MEM_WRITE != 0
    }

    /// Check if section is readable
    pub fn is_readable(&self) -> bool {
        self.characteristics & section_characteristics::MEM_READ != 0
    }

    /// Check if section is shared
    pub fn is_shared(&self) -> bool {
        self.characteristics & section_characteristics::MEM_SHARED != 0
    }

    /// Check if section contains code
    pub fn contains_code(&self) -> bool {
        self.characteristics & section_characteristics::CNT_CODE != 0
    }
}

/// Load configuration directory for security feature checks
#[derive(Debug, Clone, Default)]
pub struct LoadConfigDirectory {
    /// Size of the load config
    pub size: u32,
    /// Guard flags for CFG
    pub guard_flags: u32,
    /// Guard CF check function pointer
    pub guard_cf_check_function_pointer: u64,
    /// Guard CF dispatch function pointer
    pub guard_cf_dispatch_function_pointer: u64,
    /// Guard CF function table
    pub guard_cf_function_table: u64,
    /// Guard CF function count
    pub guard_cf_function_count: u64,
    /// Security cookie
    pub security_cookie: u64,
    /// SEH handler table
    pub seh_handler_table: u64,
    /// SEH handler count
    pub seh_handler_count: u64,
    /// Guard address taken IAT table
    pub guard_address_taken_iat_entry_table: u64,
    /// Guard address taken IAT entry count
    pub guard_address_taken_iat_entry_count: u64,
    /// Guard long jump target table
    pub guard_long_jump_target_table: u64,
    /// Guard long jump target count
    pub guard_long_jump_target_count: u64,
}

/// Debug directory information
#[derive(Debug, Clone)]
pub struct DebugDirectory {
    /// Debug type
    pub debug_type: u32,
    /// PDB path if available
    pub pdb_path: Option<String>,
    /// PDB GUID if available
    pub pdb_guid: Option<String>,
    /// PDB age
    pub pdb_age: u32,
}

/// PE binary representation
pub struct PeBinary {
    /// Path to the binary
    path: PathBuf,
    /// Raw file data (heap-allocated or memory-mapped)
    data: BinaryData,
    /// Whether the binary is valid
    valid: bool,
    /// Load error if any
    load_error: Option<String>,
    /// Whether this is a 64-bit binary
    is_64_bit: bool,
    /// Whether this is a DLL
    is_dll: bool,
    /// Whether this is an executable
    is_executable: bool,
    /// Whether this is a driver
    is_driver: bool,
    /// Whether this is a .NET/managed binary
    is_dotnet: bool,
    /// File characteristics
    pub file_characteristics: u16,
    /// DLL characteristics
    pub dll_characteristics: u16,
    /// Sections
    pub sections: Vec<SectionInfo>,
    /// Image base
    pub image_base: u64,
    /// Entry point RVA
    pub entry_point: u32,
    /// Machine type
    pub machine: u16,
    /// Linker version major
    pub linker_version_major: u8,
    /// Linker version minor
    pub linker_version_minor: u8,
    /// Load configuration directory
    pub load_config: Option<LoadConfigDirectory>,
    /// Debug directories
    pub debug_directories: Vec<DebugDirectory>,
    /// Section alignment
    pub section_alignment: u32,
    /// File alignment
    pub file_alignment: u32,
    /// OS version major
    pub os_version_major: u16,
    /// OS version minor
    pub os_version_minor: u16,
    /// Subsystem (console, GUI, driver, etc.)
    pub subsystem: u16,
    /// CLR runtime header RVA (for .NET detection)
    pub clr_runtime_header_rva: u32,
    /// CLR runtime header size
    pub clr_runtime_header_size: u32,
    /// Whether the PE has a certificate table (Authenticode)
    pub has_certificate_table: bool,
}

impl PeBinary {
    /// Minimum load config size for 32-bit
    pub const LOAD_CONFIG_MIN_SIZE_32: u32 = 0x005C;
    /// Minimum load config size for 64-bit
    pub const LOAD_CONFIG_MIN_SIZE_64: u32 = 0x0090;

    /// Load a PE binary from a file using the default memory budget
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        Self::load_with_budget(path, &MemoryBudget::default())
    }

    /// Load a PE binary from a file with a custom memory budget
    pub fn load_with_budget(path: impl AsRef<Path>, budget: &MemoryBudget) -> Result<Self> {
        let path = path.as_ref();
        let data = budget
            .load(path)
            .map_err(|e| AldurError::binary_load(path.display().to_string(), e.to_string()))?;
        Self::parse(path.to_path_buf(), data)
    }

    /// Load a PE binary from raw bytes (e.g., extracted from an archive)
    pub fn load_from_bytes(path: PathBuf, bytes: Vec<u8>) -> Result<Self> {
        Self::parse(path, BinaryData::Owned(bytes))
    }

    fn parse(path: PathBuf, data: BinaryData) -> Result<Self> {
        let pe = PE::parse(&data).map_err(|e| AldurError::PEParseError(e.to_string()))?;

        // Extract all data from pe before moving mmap into binary
        let is_64_bit = pe.is_64;
        let is_dll = pe.is_lib;
        let file_characteristics = pe.header.coff_header.characteristics;
        let machine = pe.header.coff_header.machine;
        let dll_characteristics = pe
            .header
            .optional_header
            .map(|h| h.windows_fields.dll_characteristics)
            .unwrap_or(0);
        let image_base = pe
            .header
            .optional_header
            .map(|h| h.windows_fields.image_base)
            .unwrap_or(0);
        let entry_point = pe
            .header
            .optional_header
            .map(|h| h.standard_fields.address_of_entry_point)
            .unwrap_or(0);
        let linker_version_major = pe
            .header
            .optional_header
            .map(|h| h.standard_fields.major_linker_version)
            .unwrap_or(0);
        let linker_version_minor = pe
            .header
            .optional_header
            .map(|h| h.standard_fields.minor_linker_version)
            .unwrap_or(0);
        let section_alignment = pe
            .header
            .optional_header
            .map(|h| h.windows_fields.section_alignment)
            .unwrap_or(0);
        let file_alignment = pe
            .header
            .optional_header
            .map(|h| h.windows_fields.file_alignment)
            .unwrap_or(0);
        let os_version_major = pe
            .header
            .optional_header
            .map(|h| h.windows_fields.major_operating_system_version)
            .unwrap_or(0);
        let os_version_minor = pe
            .header
            .optional_header
            .map(|h| h.windows_fields.minor_operating_system_version)
            .unwrap_or(0);
        let subsystem = pe
            .header
            .optional_header
            .map(|h| h.windows_fields.subsystem)
            .unwrap_or(0);
        let is_driver = subsystem == 1; // NATIVE subsystem often indicates driver

        // Check for .NET CLR runtime header (COM descriptor / CLR header)
        let (clr_runtime_header_rva, clr_runtime_header_size) = pe
            .header
            .optional_header
            .as_ref()
            .and_then(|h| h.data_directories.get_clr_runtime_header())
            .map(|dir| (dir.virtual_address, dir.size))
            .unwrap_or((0, 0));
        let is_dotnet = clr_runtime_header_rva != 0 && clr_runtime_header_size != 0;

        // Check for certificate table (Authenticode signature)
        let has_certificate_table = pe
            .header
            .optional_header
            .as_ref()
            .and_then(|h| h.data_directories.get_certificate_table())
            .map(|dir| dir.virtual_address != 0)
            .unwrap_or(false);

        // Parse sections
        let mut sections = Vec::new();
        for section in &pe.sections {
            let name = String::from_utf8_lossy(&section.name)
                .trim_end_matches('\0')
                .to_string();
            sections.push(SectionInfo {
                name,
                virtual_address: section.virtual_address,
                virtual_size: section.virtual_size,
                raw_data_size: section.size_of_raw_data,
                characteristics: section.characteristics,
            });
        }

        // Parse load config if available
        let load_config = Self::parse_load_config(&pe, &data);

        // Now we can move data
        let binary = PeBinary {
            path,
            valid: true,
            load_error: None,
            is_64_bit,
            is_dll,
            is_executable: !is_dll,
            is_driver,
            is_dotnet,
            file_characteristics,
            dll_characteristics,
            sections,
            image_base,
            entry_point,
            machine,
            linker_version_major,
            linker_version_minor,
            load_config,
            debug_directories: Vec::new(),
            section_alignment,
            file_alignment,
            os_version_major,
            os_version_minor,
            subsystem,
            clr_runtime_header_rva,
            clr_runtime_header_size,
            has_certificate_table,
            data,
        };

        Ok(binary)
    }

    fn parse_load_config(pe: &PE, data: &[u8]) -> Option<LoadConfigDirectory> {
        let optional = pe.header.optional_header?;
        let load_config_dir = optional.data_directories.get_load_config_table()?;

        if load_config_dir.virtual_address == 0 || load_config_dir.size == 0 {
            return None;
        }

        // Find the section containing the load config
        let rva = load_config_dir.virtual_address as usize;
        for section in &pe.sections {
            let section_start = section.virtual_address as usize;
            let section_end = section_start + section.virtual_size as usize;

            if rva >= section_start && rva < section_end {
                let file_offset = section.pointer_to_raw_data as usize + (rva - section_start);

                if file_offset + 4 > data.len() {
                    return None;
                }

                let size = u32::from_le_bytes([
                    data[file_offset],
                    data[file_offset + 1],
                    data[file_offset + 2],
                    data[file_offset + 3],
                ]);

                let mut config = LoadConfigDirectory {
                    size,
                    ..Default::default()
                };

                // Parse based on whether it's 64-bit or 32-bit
                if pe.is_64 {
                    // 64-bit load config parsing
                    if size >= 112 && file_offset + 112 <= data.len() {
                        config.security_cookie = u64::from_le_bytes([
                            data[file_offset + 96],
                            data[file_offset + 97],
                            data[file_offset + 98],
                            data[file_offset + 99],
                            data[file_offset + 100],
                            data[file_offset + 101],
                            data[file_offset + 102],
                            data[file_offset + 103],
                        ]);
                    }

                    // Guard CF fields (offset 112 for GuardCFCheckFunctionPointer in 64-bit)
                    if size >= 144 && file_offset + 144 <= data.len() {
                        config.guard_cf_check_function_pointer = u64::from_le_bytes([
                            data[file_offset + 112],
                            data[file_offset + 113],
                            data[file_offset + 114],
                            data[file_offset + 115],
                            data[file_offset + 116],
                            data[file_offset + 117],
                            data[file_offset + 118],
                            data[file_offset + 119],
                        ]);

                        config.guard_cf_dispatch_function_pointer = u64::from_le_bytes([
                            data[file_offset + 120],
                            data[file_offset + 121],
                            data[file_offset + 122],
                            data[file_offset + 123],
                            data[file_offset + 124],
                            data[file_offset + 125],
                            data[file_offset + 126],
                            data[file_offset + 127],
                        ]);

                        config.guard_cf_function_table = u64::from_le_bytes([
                            data[file_offset + 128],
                            data[file_offset + 129],
                            data[file_offset + 130],
                            data[file_offset + 131],
                            data[file_offset + 132],
                            data[file_offset + 133],
                            data[file_offset + 134],
                            data[file_offset + 135],
                        ]);

                        config.guard_cf_function_count = u64::from_le_bytes([
                            data[file_offset + 136],
                            data[file_offset + 137],
                            data[file_offset + 138],
                            data[file_offset + 139],
                            data[file_offset + 140],
                            data[file_offset + 141],
                            data[file_offset + 142],
                            data[file_offset + 143],
                        ]);
                    }

                    // Guard flags (offset 144 in 64-bit)
                    if size >= 148 && file_offset + 148 <= data.len() {
                        config.guard_flags = u32::from_le_bytes([
                            data[file_offset + 144],
                            data[file_offset + 145],
                            data[file_offset + 146],
                            data[file_offset + 147],
                        ]);
                    }
                } else {
                    // 32-bit load config parsing
                    if size >= 76 && file_offset + 76 <= data.len() {
                        config.security_cookie = u32::from_le_bytes([
                            data[file_offset + 60],
                            data[file_offset + 61],
                            data[file_offset + 62],
                            data[file_offset + 63],
                        ]) as u64;
                    }

                    // Guard CF fields for 32-bit
                    if size >= 92 && file_offset + 92 <= data.len() {
                        config.guard_cf_check_function_pointer = u32::from_le_bytes([
                            data[file_offset + 72],
                            data[file_offset + 73],
                            data[file_offset + 74],
                            data[file_offset + 75],
                        ]) as u64;

                        config.guard_cf_dispatch_function_pointer = u32::from_le_bytes([
                            data[file_offset + 76],
                            data[file_offset + 77],
                            data[file_offset + 78],
                            data[file_offset + 79],
                        ])
                            as u64;

                        config.guard_cf_function_table = u32::from_le_bytes([
                            data[file_offset + 80],
                            data[file_offset + 81],
                            data[file_offset + 82],
                            data[file_offset + 83],
                        ]) as u64;

                        config.guard_cf_function_count = u32::from_le_bytes([
                            data[file_offset + 84],
                            data[file_offset + 85],
                            data[file_offset + 86],
                            data[file_offset + 87],
                        ]) as u64;

                        config.guard_flags = u32::from_le_bytes([
                            data[file_offset + 88],
                            data[file_offset + 89],
                            data[file_offset + 90],
                            data[file_offset + 91],
                        ]);
                    }
                }

                return Some(config);
            }
        }

        None
    }

    /// Check if the binary has the DYNAMICBASE flag set
    pub fn is_dynamic_base(&self) -> bool {
        self.dll_characteristics & dll_characteristics::DYNAMIC_BASE != 0
    }

    /// Check if the binary has the HIGH_ENTROPY_VA flag set
    pub fn is_high_entropy_va(&self) -> bool {
        self.dll_characteristics & dll_characteristics::HIGH_ENTROPY_VA != 0
    }

    /// Check if the binary is NX compatible
    pub fn is_nx_compat(&self) -> bool {
        self.dll_characteristics & dll_characteristics::NX_COMPAT != 0
    }

    /// Check if the binary has NO_SEH flag set
    pub fn has_no_seh(&self) -> bool {
        self.dll_characteristics & dll_characteristics::NO_SEH != 0
    }

    /// Check if the binary has Control Flow Guard enabled
    pub fn has_guard_cf(&self) -> bool {
        self.dll_characteristics & dll_characteristics::GUARD_CF != 0
    }

    /// Check if the binary has Force Integrity flag set
    pub fn has_force_integrity(&self) -> bool {
        self.dll_characteristics & dll_characteristics::FORCE_INTEGRITY != 0
    }

    /// Check if the binary allows isolation (NO_ISOLATION flag NOT set)
    /// When NO_ISOLATION is set, manifest-based isolation is disabled.
    pub fn allows_isolation(&self) -> bool {
        self.dll_characteristics & dll_characteristics::NO_ISOLATION == 0
    }

    /// Check if the binary has NO_ISOLATION flag set
    pub fn has_no_isolation(&self) -> bool {
        self.dll_characteristics & dll_characteristics::NO_ISOLATION != 0
    }

    /// Check if the binary has a certificate table (Authenticode signature)
    pub fn has_certificate_table(&self) -> bool {
        self.has_certificate_table
    }

    /// Check if Return Flow Guard (RFG) is enabled
    /// RFG provides additional return address protection beyond CET shadow stack
    pub fn has_rfg(&self) -> bool {
        if let Some(ref config) = self.load_config {
            let guard_flags = config.guard_flags;
            // RFG is enabled if instrumented AND enabled, OR if strict mode
            (guard_flags & guard_flags::RF_INSTRUMENTED != 0
                && guard_flags & guard_flags::RF_ENABLE != 0)
                || guard_flags & guard_flags::RF_STRICT != 0
        } else {
            false
        }
    }

    /// Check if the binary is large address aware
    pub fn is_large_address_aware(&self) -> bool {
        self.file_characteristics & file_characteristics::LARGE_ADDRESS_AWARE != 0
    }

    /// Check if relocations are stripped
    pub fn relocs_stripped(&self) -> bool {
        self.file_characteristics & file_characteristics::RELOCS_STRIPPED != 0
    }

    /// Check if CFG is properly enabled (both flag and load config)
    pub fn enables_control_flow_guard(&self) -> bool {
        if !self.has_guard_cf() {
            return false;
        }

        if let Some(ref config) = self.load_config {
            let min_size = if self.is_64_bit {
                Self::LOAD_CONFIG_MIN_SIZE_64
            } else {
                Self::LOAD_CONFIG_MIN_SIZE_32
            };

            config.size >= min_size
                && config.guard_cf_check_function_pointer != 0
                && config.guard_cf_function_table != 0
                && (config.guard_flags & guard_flags::CF_CHECKS) == guard_flags::CF_CHECKS
        } else {
            false
        }
    }

    /// Get the linker version as a tuple
    pub fn linker_version(&self) -> (u8, u8) {
        (self.linker_version_major, self.linker_version_minor)
    }

    /// Find a section by name
    pub fn find_section(&self, name: &str) -> Option<&SectionInfo> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// Get all sections that are both writable and executable
    pub fn writable_executable_sections(&self) -> Vec<&SectionInfo> {
        self.sections
            .iter()
            .filter(|s| s.is_writable() && s.is_executable())
            .collect()
    }

    /// Check if the imports section is marked as executable
    pub fn imports_section_executable(&self) -> bool {
        // Check .idata section
        if let Some(section) = self.find_section(".idata") {
            if section.is_executable() {
                return true;
            }
        }

        // Check .rdata section (imports can be merged here)
        if let Some(section) = self.find_section(".rdata") {
            if section.is_executable() {
                return true;
            }
        }

        false
    }

    /// Get the path to the associated PDB file, if any
    pub fn pdb_path(&self) -> Option<PathBuf> {
        for debug_dir in &self.debug_directories {
            if let Some(ref pdb_path) = debug_dir.pdb_path {
                let path = PathBuf::from(pdb_path);
                if path.exists() {
                    return Some(path);
                }
                if let Some(parent) = self.path.parent() {
                    if let Some(filename) = path.file_name() {
                        let local_path = parent.join(filename);
                        if local_path.exists() {
                            return Some(local_path);
                        }
                    }
                }
            }
        }
        None
    }

    /// Check if this is a .NET/managed binary
    pub fn is_dotnet(&self) -> bool {
        self.is_dotnet
    }

    /// Check if CastGuard is enabled (/guard:cast)
    /// CastGuard is indicated by the presence of the EH continuation table
    pub fn has_cast_guard(&self) -> bool {
        if let Some(ref config) = self.load_config {
            config.guard_flags & guard_flags::EH_CONTINUATION_TABLE_PRESENT != 0
        } else {
            false
        }
    }

    /// Check if the binary uses security cookie (stack protection /GS)
    /// Returns true if security cookie is used, false if SECURITY_COOKIE_UNUSED flag is set
    pub fn uses_security_cookie(&self) -> bool {
        if let Some(ref config) = self.load_config {
            // If SECURITY_COOKIE_UNUSED is set, /GS is not used
            if config.guard_flags & guard_flags::SECURITY_COOKIE_UNUSED != 0 {
                return false;
            }
            // If security_cookie is non-zero, /GS is enabled
            config.security_cookie != 0
        } else {
            // No load config means we can't verify /GS
            false
        }
    }

    /// Check if the binary has DWARF debug info (MinGW/Clang builds)
    pub fn has_dwarf_debug_info(&self) -> bool {
        // Check for .debug_info section (DWARF)
        self.find_section(".debug_info").is_some()
    }

    /// Check if the binary is an ARM64 binary
    pub fn is_arm64(&self) -> bool {
        // ARM64 machine type is 0xAA64
        self.machine == 0xAA64
    }

    /// Check if the binary is an ARM32 binary
    pub fn is_arm32(&self) -> bool {
        // ARM machine type is 0x01c0 (THUMB), 0x01c2 (THUMB2), 0x01c4 (ARMv7)
        matches!(self.machine, 0x01c0 | 0x01c2 | 0x01c4)
    }

    /// Check if the binary is an x86_64 binary
    pub fn is_x86_64(&self) -> bool {
        self.machine == 0x8664
    }

    /// Check if the binary is an x86 binary
    pub fn is_x86(&self) -> bool {
        self.machine == 0x014c
    }

    /// Get raw data for DWARF parsing
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Check if the PE imports a specific function
    pub fn has_import(&self, function_name: &str) -> bool {
        // Re-parse to get imports
        if let Ok(pe) = PE::parse(&self.data) {
            for import in pe.imports {
                if import.name.contains(function_name) {
                    return true;
                }
            }
        }
        false
    }

    /// Get list of imported DLLs
    pub fn imported_dlls(&self) -> Vec<String> {
        let mut dlls = Vec::new();
        if let Ok(pe) = PE::parse(&self.data) {
            for import in &pe.imports {
                if !dlls.contains(&import.dll.to_string()) {
                    dlls.push(import.dll.to_string());
                }
            }
        }
        dlls
    }

    /// Get list of exported symbol names
    pub fn exported_symbols(&self) -> Vec<String> {
        let mut symbols = Vec::new();
        if let Ok(pe) = PE::parse(&self.data) {
            for reexport in &pe.exports {
                if let Some(name) = reexport.name {
                    symbols.push(name.to_string());
                }
            }
        }
        symbols
    }

    /// Find symbols containing non-ASCII characters (potential Unicode obfuscation)
    pub fn find_unicode_symbols(&self) -> Vec<String> {
        let mut unicode_syms = Vec::new();
        if let Ok(pe) = PE::parse(&self.data) {
            // Check imports
            for import in pe.imports {
                if !import.name.is_ascii() {
                    unicode_syms.push(import.name.to_string());
                }
            }
            // Check exports
            for export in &pe.exports {
                if let Some(name) = export.name {
                    if !name.is_ascii() {
                        unicode_syms.push(name.to_string());
                    }
                }
            }
        }
        unicode_syms
    }

    /// Get DWARF debug info if present (for MinGW/Clang builds)
    pub fn dwarf_info(&self) -> Option<crate::DwarfInfo> {
        if self.has_dwarf_debug_info() {
            crate::DwarfInfo::parse(&self.data).ok()
        } else {
            None
        }
    }
}

impl Binary for PeBinary {
    fn path(&self) -> &Path {
        &self.path
    }

    fn format(&self) -> BinaryFormat {
        BinaryFormat::PE
    }

    fn binary_type(&self) -> BinaryType {
        if self.is_driver {
            BinaryType::Driver
        } else if self.is_dll {
            BinaryType::DynamicLibrary
        } else if self.is_executable {
            BinaryType::Executable
        } else {
            BinaryType::Unknown
        }
    }

    fn is_64_bit(&self) -> bool {
        self.is_64_bit
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
