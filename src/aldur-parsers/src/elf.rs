//! ELF (Executable and Linkable Format) binary parser
//!
//! Parses Linux/Unix ELF binaries including:
//! - ELF headers and program headers
//! - Section tables
//! - Dynamic section for security flags
//! - GNU segments (RELRO, stack)

use aldur_core::{AldurError, Binary, BinaryFormat, BinaryType, Result};
use goblin::elf::{Elf, ProgramHeader};
use std::path::{Path, PathBuf};

use crate::memory::{BinaryData, MemoryBudget};

/// ELF program header types
pub mod ph_type {
    pub const PT_NULL: u32 = 0;
    pub const PT_LOAD: u32 = 1;
    pub const PT_DYNAMIC: u32 = 2;
    pub const PT_INTERP: u32 = 3;
    pub const PT_NOTE: u32 = 4;
    pub const PT_SHLIB: u32 = 5;
    pub const PT_PHDR: u32 = 6;
    pub const PT_TLS: u32 = 7;
    pub const PT_GNU_EH_FRAME: u32 = 0x6474e550;
    pub const PT_GNU_STACK: u32 = 0x6474e551;
    pub const PT_GNU_RELRO: u32 = 0x6474e552;
}

/// ELF program header flags
pub mod ph_flags {
    pub const PF_X: u32 = 1; // Executable
    pub const PF_W: u32 = 2; // Writable
    pub const PF_R: u32 = 4; // Readable
}

/// ELF dynamic section tags
pub mod dyn_tag {
    pub const DT_NULL: u64 = 0;
    pub const DT_NEEDED: u64 = 1;
    pub const DT_PLTRELSZ: u64 = 2;
    pub const DT_PLTGOT: u64 = 3;
    pub const DT_HASH: u64 = 4;
    pub const DT_STRTAB: u64 = 5;
    pub const DT_SYMTAB: u64 = 6;
    pub const DT_RELA: u64 = 7;
    pub const DT_RELASZ: u64 = 8;
    pub const DT_RELAENT: u64 = 9;
    pub const DT_STRSZ: u64 = 10;
    pub const DT_SYMENT: u64 = 11;
    pub const DT_INIT: u64 = 12;
    pub const DT_FINI: u64 = 13;
    pub const DT_SONAME: u64 = 14;
    pub const DT_RPATH: u64 = 15;
    pub const DT_SYMBOLIC: u64 = 16;
    pub const DT_REL: u64 = 17;
    pub const DT_RELSZ: u64 = 18;
    pub const DT_RELENT: u64 = 19;
    pub const DT_PLTREL: u64 = 20;
    pub const DT_DEBUG: u64 = 21;
    pub const DT_TEXTREL: u64 = 22;
    pub const DT_JMPREL: u64 = 23;
    pub const DT_BIND_NOW: u64 = 24;
    pub const DT_INIT_ARRAY: u64 = 25;
    pub const DT_FINI_ARRAY: u64 = 26;
    pub const DT_INIT_ARRAYSZ: u64 = 27;
    pub const DT_FINI_ARRAYSZ: u64 = 28;
    pub const DT_RUNPATH: u64 = 29;
    pub const DT_FLAGS: u64 = 30;
    pub const DT_FLAGS_1: u64 = 0x6ffffffb;
}

/// Dynamic flags (DT_FLAGS_1)
pub mod dyn_flags {
    pub const DF_1_NOW: u64 = 0x00000001; // Set RTLD_NOW for this object
    pub const DF_1_GLOBAL: u64 = 0x00000002; // Set RTLD_GLOBAL for this object
    pub const DF_1_GROUP: u64 = 0x00000004; // Set RTLD_GROUP for this object
    pub const DF_1_NODELETE: u64 = 0x00000008; // Set RTLD_NODELETE for this object
    pub const DF_1_LOADFLTR: u64 = 0x00000010; // Trigger filtee loading at runtime
    pub const DF_1_INITFIRST: u64 = 0x00000020; // Set RTLD_INITFIRST for this object
    pub const DF_1_NOOPEN: u64 = 0x00000040; // Set RTLD_NOOPEN for this object
    pub const DF_1_ORIGIN: u64 = 0x00000080; // $ORIGIN must be handled
    pub const DF_1_DIRECT: u64 = 0x00000100; // Direct binding enabled
    pub const DF_1_PIE: u64 = 0x08000000; // Position Independent Executable
}

/// GNU Property note types and feature bits
pub mod gnu_property {
    // Property types
    pub const GNU_PROPERTY_X86_FEATURE_1_AND: u32 = 0xc0000002;
    pub const GNU_PROPERTY_AARCH64_FEATURE_1_AND: u32 = 0xc0000000;

    // x86 feature bits (CET)
    pub const GNU_PROPERTY_X86_FEATURE_1_IBT: u32 = 1 << 0; // Indirect Branch Tracking
    pub const GNU_PROPERTY_X86_FEATURE_1_SHSTK: u32 = 1 << 1; // Shadow Stack

    // AArch64 feature bits
    pub const GNU_PROPERTY_AARCH64_FEATURE_1_BTI: u32 = 1 << 0; // Branch Target Identification
    pub const GNU_PROPERTY_AARCH64_FEATURE_1_PAC: u32 = 1 << 1; // Pointer Authentication
}

/// ELF file types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfType {
    None,
    Relocatable,
    Executable,
    SharedObject,
    Core,
    Unknown(u16),
}

impl From<u16> for ElfType {
    fn from(t: u16) -> Self {
        match t {
            0 => ElfType::None,
            1 => ElfType::Relocatable,
            2 => ElfType::Executable,
            3 => ElfType::SharedObject,
            4 => ElfType::Core,
            other => ElfType::Unknown(other),
        }
    }
}

/// Segment information
#[derive(Debug, Clone)]
pub struct SegmentInfo {
    /// Segment type
    pub p_type: u32,
    /// Segment flags
    pub p_flags: u32,
    /// Virtual address
    pub p_vaddr: u64,
    /// File offset
    pub p_offset: u64,
    /// Size in file
    pub p_filesz: u64,
    /// Size in memory
    pub p_memsz: u64,
}

impl SegmentInfo {
    /// Check if segment is executable
    pub fn is_executable(&self) -> bool {
        self.p_flags & ph_flags::PF_X != 0
    }

    /// Check if segment is writable
    pub fn is_writable(&self) -> bool {
        self.p_flags & ph_flags::PF_W != 0
    }

    /// Check if segment is readable
    pub fn is_readable(&self) -> bool {
        self.p_flags & ph_flags::PF_R != 0
    }
}

impl From<&ProgramHeader> for SegmentInfo {
    fn from(ph: &ProgramHeader) -> Self {
        Self {
            p_type: ph.p_type,
            p_flags: ph.p_flags,
            p_vaddr: ph.p_vaddr,
            p_offset: ph.p_offset,
            p_filesz: ph.p_filesz,
            p_memsz: ph.p_memsz,
        }
    }
}

/// ELF binary representation
pub struct ElfBinary {
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
    /// ELF type
    pub elf_type: ElfType,
    /// Machine type
    pub machine: u16,
    /// Program segments
    pub segments: Vec<SegmentInfo>,
    /// Entry point
    pub entry_point: u64,
    /// Has BIND_NOW flag
    pub has_bind_now: bool,
    /// Has GNU_RELRO segment
    pub has_relro: bool,
    /// Has GNU_STACK segment
    pub has_gnu_stack: bool,
    /// GNU_STACK segment flags (if present)
    pub gnu_stack_flags: Option<u32>,
    /// Has program header segment
    pub has_program_header: bool,
    /// DT_FLAGS_1 value
    pub dt_flags_1: u64,
    /// RPATH value (deprecated, security risk)
    pub rpath: Option<String>,
    /// RUNPATH value
    pub runpath: Option<String>,
    /// Has DT_TEXTREL (text relocations - security risk)
    pub has_textrel: bool,
    /// GNU Property x86 features (CET: IBT, SHSTK)
    pub gnu_property_x86_features: Option<u32>,
    /// GNU Property AArch64 features (BTI, PAC)
    pub gnu_property_aarch64_features: Option<u32>,
    /// Has .eh_frame or exception handling section
    pub has_exception_handling: bool,
    /// Whether this binary was compiled from Rust
    pub is_rust_binary: bool,
    /// Packer detection information
    pub packer_info: crate::packer::PackerInfo,
}

impl ElfBinary {
    /// Load an ELF binary from a file using the default memory budget
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        Self::load_with_budget(path, &MemoryBudget::default())
    }

    /// Load an ELF binary from a file with a custom memory budget
    pub fn load_with_budget(path: impl AsRef<Path>, budget: &MemoryBudget) -> Result<Self> {
        let path = path.as_ref();
        let data = budget
            .load(path)
            .map_err(|e| AldurError::binary_load(path.display().to_string(), e.to_string()))?;
        Self::parse(path.to_path_buf(), data)
    }

    /// Load an ELF binary from raw bytes (e.g., extracted from an archive)
    pub fn load_from_bytes(path: PathBuf, bytes: Vec<u8>) -> Result<Self> {
        Self::parse(path, BinaryData::Owned(bytes))
    }

    fn parse(path: PathBuf, data: BinaryData) -> Result<Self> {
        let elf = Elf::parse(&data).map_err(|e| AldurError::ElfParseError(e.to_string()))?;

        // Extract all data we need from the elf before moving data
        let is_64_bit = elf.is_64;
        let elf_type = ElfType::from(elf.header.e_type);
        let machine = elf.header.e_machine;
        let entry_point = elf.entry;

        // Parse program headers first
        let mut segments = Vec::new();
        let mut has_bind_now = false;
        let mut has_relro = false;
        let mut has_gnu_stack = false;
        let mut gnu_stack_flags = None;
        let mut has_program_header = false;
        let mut dt_flags_1 = 0u64;
        let mut rpath: Option<String> = None;
        let mut runpath: Option<String> = None;
        let mut has_textrel = false;
        let mut gnu_property_x86_features: Option<u32> = None;
        let mut gnu_property_aarch64_features: Option<u32> = None;

        for ph in &elf.program_headers {
            segments.push(SegmentInfo::from(ph));

            match ph.p_type {
                ph_type::PT_GNU_RELRO => {
                    has_relro = true;
                }
                ph_type::PT_GNU_STACK => {
                    has_gnu_stack = true;
                    gnu_stack_flags = Some(ph.p_flags);
                }
                ph_type::PT_PHDR => {
                    has_program_header = true;
                }
                _ => {}
            }
        }

        // Check for BIND_NOW, RPATH, RUNPATH, TEXTREL in dynamic entries
        if let Some(ref dynamic) = elf.dynamic {
            for dyn_entry in &dynamic.dyns {
                match dyn_entry.d_tag {
                    d if d == dyn_tag::DT_BIND_NOW => {
                        has_bind_now = true;
                    }
                    d if d == dyn_tag::DT_FLAGS_1 => {
                        dt_flags_1 = dyn_entry.d_val;
                        if dyn_entry.d_val & 0x1 != 0 {
                            has_bind_now = true;
                        }
                    }
                    d if d == dyn_tag::DT_RPATH => {
                        if let Some(ref dynstrtab) = elf.dynstrtab.get_at(dyn_entry.d_val as usize)
                        {
                            rpath = Some(dynstrtab.to_string());
                        }
                    }
                    d if d == dyn_tag::DT_RUNPATH => {
                        if let Some(ref dynstrtab) = elf.dynstrtab.get_at(dyn_entry.d_val as usize)
                        {
                            runpath = Some(dynstrtab.to_string());
                        }
                    }
                    d if d == dyn_tag::DT_TEXTREL => {
                        has_textrel = true;
                    }
                    _ => {}
                }
            }
        }

        // Parse .note.gnu.property for CET and ARM features
        if let Some(note_section) = elf.section_headers.iter().find(|sh| {
            elf.shdr_strtab
                .get_at(sh.sh_name)
                .map(|n| n == ".note.gnu.property")
                .unwrap_or(false)
        }) {
            let offset = note_section.sh_offset as usize;
            let size = note_section.sh_size as usize;
            if offset + size <= data.len() {
                let note_data = &data[offset..offset + size];
                let (x86_features, aarch64_features) =
                    parse_gnu_property_notes(note_data, is_64_bit);
                gnu_property_x86_features = x86_features;
                gnu_property_aarch64_features = aarch64_features;
            }
        }

        // Check for exception handling sections (.eh_frame, .eh_frame_hdr, .gcc_except_table)
        let has_exception_handling = elf.section_headers.iter().any(|sh| {
            elf.shdr_strtab
                .get_at(sh.sh_name)
                .map(|name| matches!(name, ".eh_frame" | ".eh_frame_hdr" | ".gcc_except_table"))
                .unwrap_or(false)
        });

        // Detect if this is a Rust binary by looking for Rust-specific symbols
        let is_rust_binary = detect_rust_binary(&elf);

        // Collect section names for packer detection
        let section_names: Vec<String> = elf
            .section_headers
            .iter()
            .filter_map(|sh| elf.shdr_strtab.get_at(sh.sh_name).map(|s| s.to_string()))
            .collect();
        let section_name_refs: Vec<&str> = section_names.iter().map(|s| s.as_str()).collect();

        // Detect if the binary is packed
        let packer_info = crate::packer::detect_packer(&data, &section_name_refs);

        let binary = ElfBinary {
            path,
            valid: true,
            load_error: None,
            is_64_bit,
            elf_type,
            machine,
            segments,
            entry_point,
            has_bind_now,
            has_relro,
            has_gnu_stack,
            gnu_stack_flags,
            has_program_header,
            dt_flags_1,
            rpath,
            runpath,
            has_textrel,
            gnu_property_x86_features,
            gnu_property_aarch64_features,
            has_exception_handling,
            is_rust_binary,
            packer_info,
            data,
        };

        Ok(binary)
    }

    /// Get the path to this binary
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get the raw binary data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Check if this binary appears to be packed
    pub fn is_packed(&self) -> bool {
        self.packer_info.is_packed
    }

    /// Get packer information
    pub fn packer_info(&self) -> &crate::packer::PackerInfo {
        &self.packer_info
    }

    /// Check if this is a Position Independent Executable (PIE)
    pub fn is_pie(&self) -> bool {
        // A PIE is a shared object with a program header segment
        self.elf_type == ElfType::SharedObject && self.has_program_header
    }

    /// Check if this is a shared library (not a PIE executable)
    pub fn is_shared_library(&self) -> bool {
        self.elf_type == ElfType::SharedObject && !self.has_program_header
    }

    /// Check if this is a relocatable object file (.o)
    /// Object files are intermediate build artifacts; linker-level security
    /// flags are not applicable to them.
    pub fn is_object_file(&self) -> bool {
        self.elf_type == ElfType::Relocatable
    }

    /// Check if the stack is executable
    pub fn has_executable_stack(&self) -> bool {
        if let Some(flags) = self.gnu_stack_flags {
            flags & ph_flags::PF_X != 0
        } else {
            // If no GNU_STACK segment, stack may be executable (legacy behavior)
            !self.has_gnu_stack
        }
    }

    /// Check if stack is non-executable (NX)
    pub fn has_non_executable_stack(&self) -> bool {
        !self.has_executable_stack()
    }

    /// Check if RELRO is enabled
    pub fn has_read_only_relocations(&self) -> bool {
        self.has_relro
    }

    /// Check if full RELRO is enabled (RELRO + BIND_NOW)
    pub fn has_full_relro(&self) -> bool {
        self.has_relro && self.has_bind_now
    }

    /// Get the GNU_STACK segment if present
    pub fn gnu_stack_segment(&self) -> Option<&SegmentInfo> {
        self.segments
            .iter()
            .find(|s| s.p_type == ph_type::PT_GNU_STACK)
    }

    /// Get the GNU_RELRO segment if present
    pub fn gnu_relro_segment(&self) -> Option<&SegmentInfo> {
        self.segments
            .iter()
            .find(|s| s.p_type == ph_type::PT_GNU_RELRO)
    }

    /// Check if the binary has any of the specified symbols
    pub fn has_any_symbol(&self, symbols: &[&str]) -> bool {
        // Re-parse the ELF to get symbols
        if let Ok(elf) = Elf::parse(&self.data) {
            // Check dynamic symbols
            for sym in elf.dynsyms.iter() {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    if symbols.iter().any(|s| name.contains(s)) {
                        return true;
                    }
                }
            }
            // Check regular symbols
            for sym in elf.syms.iter() {
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    if symbols.iter().any(|s| name.contains(s)) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check if the binary has a specific symbol (substring match)
    pub fn has_symbol(&self, symbol: &str) -> bool {
        self.has_any_symbol(&[symbol])
    }

    /// Check if the binary has any of the specified symbols (exact match)
    pub fn has_any_symbol_exact(&self, symbols: &[&str]) -> bool {
        if let Ok(elf) = Elf::parse(&self.data) {
            // Check dynamic symbols
            for sym in elf.dynsyms.iter() {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    // Strip version suffix (e.g., "foo@GLIBC_2.2.5" -> "foo")
                    let base_name = name.split('@').next().unwrap_or(name);
                    if symbols.contains(&base_name) {
                        return true;
                    }
                }
            }
            // Check regular symbols
            for sym in elf.syms.iter() {
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    let base_name = name.split('@').next().unwrap_or(name);
                    if symbols.contains(&base_name) {
                        return true;
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

    /// Get the list of shared libraries this binary depends on (DT_NEEDED entries)
    pub fn get_needed_libraries(&self) -> Vec<String> {
        let mut libs = Vec::new();
        if let Ok(elf) = Elf::parse(&self.data) {
            if let Some(ref dynamic) = elf.dynamic {
                for dyn_entry in &dynamic.dyns {
                    if dyn_entry.d_tag == dyn_tag::DT_NEEDED {
                        if let Some(name) = elf.dynstrtab.get_at(dyn_entry.d_val as usize) {
                            libs.push(name.to_string());
                        }
                    }
                }
            }
        }
        libs
    }

    /// Check if the binary dynamically links to a specific library (by name substring)
    pub fn links_to_library(&self, lib_name: &str) -> bool {
        self.get_needed_libraries()
            .iter()
            .any(|lib| lib.contains(lib_name))
    }

    /// Get all symbol names from the binary
    pub fn get_all_symbol_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        if let Ok(elf) = Elf::parse(&self.data) {
            // Get dynamic symbol names
            for sym in elf.dynsyms.iter() {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        names.push(name.to_string());
                    }
                }
            }
            // Get regular symbol names
            for sym in elf.syms.iter() {
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        names.push(name.to_string());
                    }
                }
            }
        }
        names
    }

    /// Find symbols containing non-ASCII characters (potential Unicode obfuscation)
    pub fn find_unicode_symbols(&self) -> Vec<String> {
        self.get_all_symbol_names()
            .into_iter()
            .filter(|name| !name.is_ascii())
            .collect()
    }

    /// Check if the binary has RPATH set (deprecated, security risk)
    pub fn has_rpath(&self) -> bool {
        self.rpath.is_some()
    }

    /// Check if the binary has RUNPATH set
    pub fn has_runpath(&self) -> bool {
        self.runpath.is_some()
    }

    /// Check if Intel CET IBT (Indirect Branch Tracking) is enabled
    pub fn has_intel_cet_ibt(&self) -> bool {
        self.gnu_property_x86_features
            .map(|f| f & gnu_property::GNU_PROPERTY_X86_FEATURE_1_IBT != 0)
            .unwrap_or(false)
    }

    /// Check if Intel CET Shadow Stack is enabled
    pub fn has_intel_cet_shstk(&self) -> bool {
        self.gnu_property_x86_features
            .map(|f| f & gnu_property::GNU_PROPERTY_X86_FEATURE_1_SHSTK != 0)
            .unwrap_or(false)
    }

    /// Check if ARM BTI (Branch Target Identification) is enabled
    pub fn has_arm_bti(&self) -> bool {
        self.gnu_property_aarch64_features
            .map(|f| f & gnu_property::GNU_PROPERTY_AARCH64_FEATURE_1_BTI != 0)
            .unwrap_or(false)
    }

    /// Check if ARM PAC (Pointer Authentication) is enabled
    pub fn has_arm_pac(&self) -> bool {
        self.gnu_property_aarch64_features
            .map(|f| f & gnu_property::GNU_PROPERTY_AARCH64_FEATURE_1_PAC != 0)
            .unwrap_or(false)
    }

    /// Check if this is an x86_64 binary
    pub fn is_x86_64(&self) -> bool {
        self.machine == 0x3E // EM_X86_64
    }

    /// Check if this is an AArch64 binary
    pub fn is_aarch64(&self) -> bool {
        self.machine == 0xB7 // EM_AARCH64
    }

    /// Check if the binary has exception handling frames (.eh_frame, .eh_frame_hdr)
    /// These are recommended for multi-threaded C code with pthreads
    pub fn has_exception_handling(&self) -> bool {
        if let Ok(elf) = Elf::parse(&self.data) {
            for section in &elf.section_headers {
                if let Some(".eh_frame" | ".eh_frame_hdr" | ".gcc_except_table") =
                    elf.shdr_strtab.get_at(section.sh_name)
                {
                    return true;
                }
            }
        }
        false
    }

    /// Check if the binary has a specific section by name
    pub fn has_section(&self, section_name: &str) -> bool {
        if let Ok(elf) = Elf::parse(&self.data) {
            for section in &elf.section_headers {
                if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                    if name == section_name {
                        return true;
                    }
                }
            }
        }
        false
    }
}

/// Detect if a binary was compiled from Rust by looking for Rust-specific symbols
///
/// Rust binaries typically contain symbols like:
/// - `rust_begin_unwind` or `rust_panic` (panic handling)
/// - `__rust_alloc`, `__rust_dealloc`, `__rust_realloc` (Rust allocator)
/// - Symbols starting with `_RN` (Rust v0 name mangling)
/// - Symbols starting with `_ZN` containing "rustc" (Rust legacy mangling)
fn detect_rust_binary(elf: &Elf) -> bool {
    // Rust-specific symbol patterns to look for
    let rust_indicators = [
        "rust_begin_unwind",
        "rust_panic",
        "__rust_alloc",
        "__rust_dealloc",
        "__rust_realloc",
        "_RNvCs", // Rust v0 mangled symbol prefix
    ];

    // Check both dynamic and regular symbols
    let check_symbol =
        |name: &str| -> bool { rust_indicators.iter().any(|pattern| name.contains(pattern)) };

    // Check dynamic symbols
    for sym in elf.dynsyms.iter() {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            if check_symbol(name) {
                return true;
            }
        }
    }

    // Check regular symbols
    for sym in elf.syms.iter() {
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            if check_symbol(name) {
                return true;
            }
        }
    }

    false
}

/// Parse GNU property notes to extract x86 and AArch64 feature flags
fn parse_gnu_property_notes(data: &[u8], is_64_bit: bool) -> (Option<u32>, Option<u32>) {
    let mut x86_features: Option<u32> = None;
    let mut aarch64_features: Option<u32> = None;

    // Note format: namesz (4), descsz (4), type (4), name (aligned), desc (aligned)
    let align = if is_64_bit { 8 } else { 4 };
    let mut offset = 0;

    while offset + 12 <= data.len() {
        let namesz = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        let descsz = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]) as usize;
        let note_type = u32::from_le_bytes([
            data[offset + 8],
            data[offset + 9],
            data[offset + 10],
            data[offset + 11],
        ]);

        offset += 12;

        // Align name size
        let aligned_namesz = (namesz + align - 1) & !(align - 1);
        if offset + aligned_namesz > data.len() {
            break;
        }

        // Check for "GNU\0" name and NT_GNU_PROPERTY_TYPE_0 (5)
        let is_gnu_property = namesz == 4
            && offset + 4 <= data.len()
            && &data[offset..offset + 4] == b"GNU\0"
            && note_type == 5;

        offset += aligned_namesz;

        let aligned_descsz = (descsz + align - 1) & !(align - 1);
        if offset + aligned_descsz > data.len() {
            break;
        }

        if is_gnu_property && descsz >= 8 {
            // Parse property entries within the descriptor
            let desc_end = offset + descsz;
            let mut prop_offset = offset;

            while prop_offset + 8 <= desc_end {
                let prop_type = u32::from_le_bytes([
                    data[prop_offset],
                    data[prop_offset + 1],
                    data[prop_offset + 2],
                    data[prop_offset + 3],
                ]);
                let prop_size = u32::from_le_bytes([
                    data[prop_offset + 4],
                    data[prop_offset + 5],
                    data[prop_offset + 6],
                    data[prop_offset + 7],
                ]) as usize;

                prop_offset += 8;

                if prop_offset + prop_size > desc_end {
                    break;
                }

                if prop_size >= 4 {
                    let value = u32::from_le_bytes([
                        data[prop_offset],
                        data[prop_offset + 1],
                        data[prop_offset + 2],
                        data[prop_offset + 3],
                    ]);

                    match prop_type {
                        gnu_property::GNU_PROPERTY_X86_FEATURE_1_AND => {
                            x86_features = Some(value);
                        }
                        gnu_property::GNU_PROPERTY_AARCH64_FEATURE_1_AND => {
                            aarch64_features = Some(value);
                        }
                        _ => {}
                    }
                }

                // Align to next property
                let aligned_prop_size = (prop_size + align - 1) & !(align - 1);
                prop_offset += aligned_prop_size;
            }
        }

        offset += aligned_descsz;
    }

    (x86_features, aarch64_features)
}

impl Binary for ElfBinary {
    fn path(&self) -> &Path {
        &self.path
    }

    fn format(&self) -> BinaryFormat {
        BinaryFormat::ELF
    }

    fn binary_type(&self) -> BinaryType {
        match self.elf_type {
            ElfType::Executable => BinaryType::Executable,
            ElfType::SharedObject => {
                if self.is_pie() {
                    BinaryType::Executable
                } else {
                    BinaryType::DynamicLibrary
                }
            }
            ElfType::Relocatable => BinaryType::Object,
            ElfType::Core => BinaryType::Core,
            _ => BinaryType::Unknown,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // Helper to get path to test fixtures
    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("test-fixtures")
    }

    #[test]
    fn test_load_hardened_binary() {
        let binary = ElfBinary::load(fixtures_dir().join("hardened")).unwrap();
        assert!(binary.is_valid());
        assert!(binary.is_64_bit);
        assert!(binary.is_pie());
        assert!(binary.has_relro);
        assert!(binary.has_bind_now);
        assert!(binary.has_full_relro());
        assert!(!binary.has_executable_stack());
        assert!(binary.has_non_executable_stack());
    }

    #[test]
    fn test_no_pie_binary() {
        let binary = ElfBinary::load(fixtures_dir().join("no_pie")).unwrap();
        assert!(binary.is_valid());
        assert!(!binary.is_pie());
        assert_eq!(binary.elf_type, ElfType::Executable);
    }

    #[test]
    fn test_no_stack_protector_binary() {
        // Note: Stack protector is detected via symbols, not ELF flags
        let binary = ElfBinary::load(fixtures_dir().join("no_stack_protector")).unwrap();
        assert!(binary.is_valid());
        // Without stack protector, shouldn't have __stack_chk_fail
        let has_stack_chk = binary.has_symbol("__stack_chk_fail");
        assert!(!has_stack_chk);
    }

    #[test]
    fn test_partial_relro_binary() {
        let binary = ElfBinary::load(fixtures_dir().join("partial_relro")).unwrap();
        assert!(binary.is_valid());
        assert!(binary.has_relro);
        assert!(!binary.has_bind_now);
        assert!(!binary.has_full_relro());
    }

    #[test]
    fn test_no_relro_binary() {
        let binary = ElfBinary::load(fixtures_dir().join("no_relro")).unwrap();
        assert!(binary.is_valid());
        assert!(!binary.has_relro);
        assert!(!binary.has_full_relro());
    }

    #[test]
    fn test_exec_stack_binary() {
        let binary = ElfBinary::load(fixtures_dir().join("exec_stack")).unwrap();
        assert!(binary.is_valid());
        assert!(binary.has_executable_stack());
        assert!(!binary.has_non_executable_stack());
    }

    #[test]
    fn test_rpath_binary() {
        let binary = ElfBinary::load(fixtures_dir().join("with_rpath")).unwrap();
        assert!(binary.is_valid());
        assert!(binary.has_rpath());
        assert!(binary.rpath.is_some());
        assert!(binary.rpath.as_ref().unwrap().contains("/tmp"));
    }

    #[test]
    fn test_runpath_binary() {
        let binary = ElfBinary::load(fixtures_dir().join("with_runpath")).unwrap();
        assert!(binary.is_valid());
        assert!(binary.has_runpath());
        assert!(binary.runpath.is_some());
        assert!(binary.runpath.as_ref().unwrap().contains("/opt/lib"));
    }

    #[test]
    fn test_with_debug_binary() {
        let binary = ElfBinary::load(fixtures_dir().join("with_debug")).unwrap();
        assert!(binary.is_valid());
        assert!(binary.is_pie());
    }

    #[test]
    fn test_cet_enabled_binary() {
        let binary = ElfBinary::load(fixtures_dir().join("with_cet")).unwrap();
        assert!(binary.is_valid());
        assert!(binary.is_x86_64());
        // CET may or may not be in .note.gnu.property depending on toolchain
        // Just verify we can check for it
        let _has_ibt = binary.has_intel_cet_ibt();
        let _has_shstk = binary.has_intel_cet_shstk();
    }

    #[test]
    fn test_lto_binary() {
        let binary = ElfBinary::load(fixtures_dir().join("with_lto")).unwrap();
        assert!(binary.is_valid());
        assert!(binary.is_pie());
    }

    #[test]
    fn test_segment_info() {
        let binary = ElfBinary::load(fixtures_dir().join("hardened")).unwrap();
        assert!(!binary.segments.is_empty());

        // Check for GNU_RELRO segment
        let relro_seg = binary.gnu_relro_segment();
        assert!(relro_seg.is_some());

        // Check for GNU_STACK segment
        let stack_seg = binary.gnu_stack_segment();
        assert!(stack_seg.is_some());
        assert!(!stack_seg.unwrap().is_executable());
    }

    #[test]
    fn test_symbol_detection() {
        let binary = ElfBinary::load(fixtures_dir().join("hardened")).unwrap();
        let symbols = binary.get_all_symbol_names();
        assert!(!symbols.is_empty());

        // Check for standard C library symbols
        assert!(binary.has_any_symbol(&["printf", "puts"]));
    }

    #[test]
    fn test_unicode_symbol_detection() {
        let binary = ElfBinary::load(fixtures_dir().join("hardened")).unwrap();
        // Normal binaries shouldn't have unicode symbols
        let unicode_syms = binary.find_unicode_symbols();
        assert!(unicode_syms.is_empty());
    }

    #[test]
    fn test_elf_type_conversion() {
        assert_eq!(ElfType::from(0), ElfType::None);
        assert_eq!(ElfType::from(1), ElfType::Relocatable);
        assert_eq!(ElfType::from(2), ElfType::Executable);
        assert_eq!(ElfType::from(3), ElfType::SharedObject);
        assert_eq!(ElfType::from(4), ElfType::Core);
        assert_eq!(ElfType::from(255), ElfType::Unknown(255));
    }

    #[test]
    fn test_segment_flags() {
        let seg = SegmentInfo {
            p_type: ph_type::PT_LOAD,
            p_flags: ph_flags::PF_R | ph_flags::PF_X,
            p_vaddr: 0,
            p_offset: 0,
            p_filesz: 0,
            p_memsz: 0,
        };

        assert!(seg.is_readable());
        assert!(seg.is_executable());
        assert!(!seg.is_writable());
    }

    #[test]
    fn test_binary_format() {
        let binary = ElfBinary::load(fixtures_dir().join("hardened")).unwrap();
        assert_eq!(binary.format(), BinaryFormat::ELF);
    }

    #[test]
    fn test_system_binary_ls() {
        // Test against a real system binary for additional coverage
        let ls_path = PathBuf::from("/usr/bin/ls");
        if ls_path.exists() {
            let binary = ElfBinary::load(&ls_path).unwrap();
            assert!(binary.is_valid());
            assert!(binary.is_64_bit);
            // Most modern distros have hardened binaries
            assert!(binary.is_pie() || binary.elf_type == ElfType::Executable);
        }
    }
}
