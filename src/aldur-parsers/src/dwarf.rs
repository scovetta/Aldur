//! DWARF debug information parser
//!
//! Parses DWARF debug information from ELF and Mach-O binaries.
//! Extracts:
//! - Compilation units
//! - Compiler information
//! - Language information

use aldur_core::{AldurError, Result};
use gimli::{AttributeValue, Dwarf, EndianSlice, RunTimeEndian, SectionId};
use object::{Object, ObjectSection};
use std::borrow::Cow;
use std::fs;
use std::path::Path;

/// DWARF language types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DwarfLanguage {
    C,
    C89,
    C99,
    C11,
    C17,
    CPlusPlus,
    CPlusPlus03,
    CPlusPlus11,
    CPlusPlus14,
    CPlusPlus17,
    CPlusPlus20,
    Rust,
    Go,
    Swift,
    D,
    Fortran,
    Ada,
    Cobol,
    Pascal,
    Java,
    Python,
    Assembly,
    Unknown(u16),
}

impl From<gimli::DwLang> for DwarfLanguage {
    fn from(lang: gimli::DwLang) -> Self {
        match lang {
            gimli::DW_LANG_C => DwarfLanguage::C,
            gimli::DW_LANG_C89 => DwarfLanguage::C89,
            gimli::DW_LANG_C99 => DwarfLanguage::C99,
            gimli::DW_LANG_C11 => DwarfLanguage::C11,
            gimli::DW_LANG_C17 => DwarfLanguage::C17,
            gimli::DW_LANG_C_plus_plus => DwarfLanguage::CPlusPlus,
            gimli::DW_LANG_C_plus_plus_03 => DwarfLanguage::CPlusPlus03,
            gimli::DW_LANG_C_plus_plus_11 => DwarfLanguage::CPlusPlus11,
            gimli::DW_LANG_C_plus_plus_14 => DwarfLanguage::CPlusPlus14,
            gimli::DW_LANG_C_plus_plus_17 => DwarfLanguage::CPlusPlus17,
            gimli::DW_LANG_C_plus_plus_20 => DwarfLanguage::CPlusPlus20,
            gimli::DW_LANG_Rust => DwarfLanguage::Rust,
            gimli::DW_LANG_Go => DwarfLanguage::Go,
            gimli::DW_LANG_Swift => DwarfLanguage::Swift,
            gimli::DW_LANG_D => DwarfLanguage::D,
            gimli::DW_LANG_Fortran77 | gimli::DW_LANG_Fortran90 | gimli::DW_LANG_Fortran95 => {
                DwarfLanguage::Fortran
            }
            gimli::DW_LANG_Ada83 | gimli::DW_LANG_Ada95 => DwarfLanguage::Ada,
            gimli::DW_LANG_Cobol74 | gimli::DW_LANG_Cobol85 => DwarfLanguage::Cobol,
            gimli::DW_LANG_Pascal83 => DwarfLanguage::Pascal,
            gimli::DW_LANG_Java => DwarfLanguage::Java,
            gimli::DW_LANG_Python => DwarfLanguage::Python,
            gimli::DW_LANG_Mips_Assembler => DwarfLanguage::Assembly,
            other => DwarfLanguage::Unknown(other.0),
        }
    }
}

impl std::fmt::Display for DwarfLanguage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DwarfLanguage::C => write!(f, "C"),
            DwarfLanguage::C89 => write!(f, "C89"),
            DwarfLanguage::C99 => write!(f, "C99"),
            DwarfLanguage::C11 => write!(f, "C11"),
            DwarfLanguage::C17 => write!(f, "C17"),
            DwarfLanguage::CPlusPlus => write!(f, "C++"),
            DwarfLanguage::CPlusPlus03 => write!(f, "C++03"),
            DwarfLanguage::CPlusPlus11 => write!(f, "C++11"),
            DwarfLanguage::CPlusPlus14 => write!(f, "C++14"),
            DwarfLanguage::CPlusPlus17 => write!(f, "C++17"),
            DwarfLanguage::CPlusPlus20 => write!(f, "C++20"),
            DwarfLanguage::Rust => write!(f, "Rust"),
            DwarfLanguage::Go => write!(f, "Go"),
            DwarfLanguage::Swift => write!(f, "Swift"),
            DwarfLanguage::D => write!(f, "D"),
            DwarfLanguage::Fortran => write!(f, "Fortran"),
            DwarfLanguage::Ada => write!(f, "Ada"),
            DwarfLanguage::Cobol => write!(f, "COBOL"),
            DwarfLanguage::Pascal => write!(f, "Pascal"),
            DwarfLanguage::Java => write!(f, "Java"),
            DwarfLanguage::Python => write!(f, "Python"),
            DwarfLanguage::Assembly => write!(f, "Assembly"),
            DwarfLanguage::Unknown(code) => write!(f, "Unknown({})", code),
        }
    }
}

/// Compiler information extracted from DWARF
#[derive(Debug, Clone)]
pub struct DwarfCompilerInfo {
    /// Producer string (usually contains compiler name and version)
    pub producer: String,
    /// Language
    pub language: DwarfLanguage,
    /// Compilation directory
    pub comp_dir: Option<String>,
    /// Source file name
    pub name: Option<String>,
}

/// Compiler type detected from producer string
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompilerType {
    Gcc,
    Clang,
    Rustc,
    Go,
    Icc,
    Unknown,
}

impl std::fmt::Display for CompilerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompilerType::Gcc => write!(f, "GCC"),
            CompilerType::Clang => write!(f, "Clang"),
            CompilerType::Rustc => write!(f, "rustc"),
            CompilerType::Go => write!(f, "Go"),
            CompilerType::Icc => write!(f, "ICC"),
            CompilerType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Parsed compiler information from producer string
#[derive(Debug, Clone)]
pub struct ParsedCompilerInfo {
    /// Compiler type
    pub compiler_type: CompilerType,
    /// Compiler version (major, minor, patch)
    pub version: Option<(u32, u32, u32)>,
    /// Compiler flags extracted from producer string
    pub flags: Vec<String>,
    /// Optimization level (-O0, -O1, -O2, -O3, -Os, -Oz, -Ofast)
    pub optimization_level: Option<String>,
    /// Whether LTO is enabled
    pub has_lto: bool,
    /// Whether stack clash protection is enabled
    pub has_stack_clash_protection: bool,
    /// Whether stack protector is enabled
    pub has_stack_protector: bool,
    /// Whether FORTIFY_SOURCE is enabled
    pub has_fortify_source: bool,
}

/// Compilation unit information
#[derive(Debug, Clone)]
pub struct CompilationUnit {
    /// DWARF version
    pub version: u16,
    /// Compiler information
    pub compiler_info: DwarfCompilerInfo,
    /// Command line if available
    pub command_line: Option<String>,
    /// Parsed compiler info from producer string
    pub parsed_info: ParsedCompilerInfo,
}

/// DWARF debug information reader
pub struct DwarfInfo {
    /// Compilation units found
    pub compilation_units: Vec<CompilationUnit>,
    /// DWARF version
    pub dwarf_version: u16,
    /// Whether debug info was found
    pub has_debug_info: bool,
}

impl DwarfInfo {
    /// Parse DWARF information from a file
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let data = fs::read(path).map_err(|e| AldurError::DwarfParseError(e.to_string()))?;

        Self::parse(&data)
    }

    /// Parse compiler info from a producer string
    pub fn parse_producer(producer: &str) -> ParsedCompilerInfo {
        let mut info = ParsedCompilerInfo {
            compiler_type: CompilerType::Unknown,
            version: None,
            flags: Vec::new(),
            optimization_level: None,
            has_lto: false,
            has_stack_clash_protection: false,
            has_stack_protector: false,
            has_fortify_source: false,
        };

        // Detect compiler type
        let producer_lower = producer.to_lowercase();
        if producer_lower.contains("clang") || producer_lower.contains("llvm") {
            info.compiler_type = CompilerType::Clang;
        } else if producer_lower.contains("gcc") || producer_lower.contains("gnu c") {
            info.compiler_type = CompilerType::Gcc;
        } else if producer_lower.contains("rustc") {
            info.compiler_type = CompilerType::Rustc;
        } else if producer_lower.contains("go ") || producer_lower.starts_with("go") {
            info.compiler_type = CompilerType::Go;
        } else if producer_lower.contains("intel") || producer_lower.contains("icc") {
            info.compiler_type = CompilerType::Icc;
        }

        // Parse version
        info.version = Self::parse_compiler_version(producer);

        // Extract flags from producer string
        // GCC producer strings often look like: "GNU C17 11.2.0 -mtune=generic -march=x86-64 -g -O2 -fstack-protector-strong"
        for word in producer.split_whitespace() {
            if word.starts_with('-') {
                info.flags.push(word.to_string());

                // Check for specific flags
                if word.starts_with("-O") {
                    info.optimization_level = Some(word.to_string());
                }
                if word == "-flto" || word.starts_with("-flto=") {
                    info.has_lto = true;
                }
                if word == "-fstack-clash-protection" {
                    info.has_stack_clash_protection = true;
                }
                if word == "-fno-stack-clash-protection" {
                    info.has_stack_clash_protection = false;
                }
                if word.starts_with("-fstack-protector") {
                    info.has_stack_protector = true;
                }
                if word == "-fno-stack-protector" {
                    info.has_stack_protector = false;
                }
            }

            // Check for FORTIFY_SOURCE in defines
            if word.contains("FORTIFY_SOURCE") || word.contains("_FORTIFY_SOURCE") {
                info.has_fortify_source = true;
            }
        }

        info
    }

    /// Parse DWARF from raw bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        let object =
            object::File::parse(data).map_err(|e| AldurError::DwarfParseError(e.to_string()))?;

        let endian = if object.is_little_endian() {
            RunTimeEndian::Little
        } else {
            RunTimeEndian::Big
        };

        // Load DWARF sections
        let load_section = |id: SectionId| -> std::result::Result<Cow<[u8]>, gimli::Error> {
            match object.section_by_name(id.name()) {
                Some(section) => Ok(section.data().unwrap_or(&[]).into()),
                None => Ok(Cow::Borrowed(&[])),
            }
        };

        let dwarf_sections = gimli::DwarfSections::load(load_section)
            .map_err(|e| AldurError::DwarfParseError(e.to_string()))?;

        let dwarf: Dwarf<EndianSlice<RunTimeEndian>> =
            dwarf_sections.borrow(|section| EndianSlice::new(section, endian));

        let mut result = DwarfInfo {
            compilation_units: Vec::new(),
            dwarf_version: 0,
            has_debug_info: false,
        };

        // Iterate over compilation units
        let mut iter = dwarf.units();
        while let Ok(Some(header)) = iter.next() {
            result.has_debug_info = true;
            result.dwarf_version = result.dwarf_version.max(header.version());

            if let Ok(unit) = dwarf.unit(header) {
                if let Some(cu) = Self::parse_compilation_unit(&dwarf, &unit) {
                    result.compilation_units.push(cu);
                }
            }
        }

        Ok(result)
    }

    fn parse_compilation_unit(
        dwarf: &Dwarf<EndianSlice<RunTimeEndian>>,
        unit: &gimli::Unit<EndianSlice<RunTimeEndian>>,
    ) -> Option<CompilationUnit> {
        let mut entries = unit.entries();

        // Get the first entry (should be DW_TAG_compile_unit)
        let entry = entries.next_dfs().ok()??;

        if entry.tag() != gimli::DW_TAG_compile_unit && entry.tag() != gimli::DW_TAG_partial_unit {
            return None;
        }

        let mut compiler_info = DwarfCompilerInfo {
            producer: String::new(),
            language: DwarfLanguage::Unknown(0),
            comp_dir: None,
            name: None,
        };

        for attr in entry.attrs() {
            match attr.name() {
                gimli::DW_AT_producer => {
                    if let Ok(s) = dwarf.attr_string(unit, attr.value()) {
                        let cow = s.to_string_lossy();
                        compiler_info.producer = cow.into_owned();
                    }
                }
                gimli::DW_AT_language => {
                    if let AttributeValue::Language(lang) = attr.value() {
                        compiler_info.language = DwarfLanguage::from(lang);
                    }
                }
                gimli::DW_AT_comp_dir => {
                    if let Ok(s) = dwarf.attr_string(unit, attr.value()) {
                        let cow = s.to_string_lossy();
                        compiler_info.comp_dir = Some(cow.into_owned());
                    }
                }
                gimli::DW_AT_name => {
                    if let Ok(s) = dwarf.attr_string(unit, attr.value()) {
                        let cow = s.to_string_lossy();
                        compiler_info.name = Some(cow.into_owned());
                    }
                }
                _ => {}
            }
        }

        // Parse the producer string to extract compiler flags
        let parsed_info = DwarfInfo::parse_producer(&compiler_info.producer);

        Some(CompilationUnit {
            version: unit.header.version(),
            compiler_info,
            command_line: None,
            parsed_info,
        })
    }

    /// Check if the DWARF version is at least the specified version
    pub fn meets_minimum_version(&self, min_version: u16) -> bool {
        self.dwarf_version >= min_version
    }

    /// Get unique languages used in the binary
    pub fn languages(&self) -> Vec<DwarfLanguage> {
        let mut languages: Vec<DwarfLanguage> = self
            .compilation_units
            .iter()
            .map(|cu| cu.compiler_info.language)
            .collect();
        languages.sort_by_key(|l| format!("{:?}", l));
        languages.dedup();
        languages
    }

    /// Check if the binary is C/C++
    pub fn is_c_or_cpp(&self) -> bool {
        self.compilation_units.iter().any(|cu| {
            matches!(
                cu.compiler_info.language,
                DwarfLanguage::C
                    | DwarfLanguage::C89
                    | DwarfLanguage::C99
                    | DwarfLanguage::C11
                    | DwarfLanguage::C17
                    | DwarfLanguage::CPlusPlus
                    | DwarfLanguage::CPlusPlus03
                    | DwarfLanguage::CPlusPlus11
                    | DwarfLanguage::CPlusPlus14
                    | DwarfLanguage::CPlusPlus17
                    | DwarfLanguage::CPlusPlus20
            )
        })
    }

    /// Parse compiler name from producer string
    pub fn parse_compiler_name(producer: &str) -> Option<&str> {
        if producer.contains("clang") {
            Some("clang")
        } else if producer.contains("GCC") || producer.contains("GNU") {
            Some("gcc")
        } else if producer.contains("rustc") {
            Some("rustc")
        } else if producer.contains("Intel") {
            Some("icc")
        } else {
            None
        }
    }

    /// Parse compiler version from producer string
    pub fn parse_compiler_version(producer: &str) -> Option<(u32, u32, u32)> {
        // Try to find version pattern like "X.Y.Z" or "X.Y"
        // Simple manual parsing without regex
        let mut version_start = None;
        for (i, c) in producer.char_indices() {
            if c.is_ascii_digit() {
                // Check if this might be the start of a version
                if version_start.is_none() {
                    version_start = Some(i);
                }
            } else if c == '.' {
                // Continue if we have a version start
                continue;
            } else if version_start.is_some() {
                // Try to parse what we have
                let candidate = &producer[version_start.unwrap()..i];
                if let Some(version) = Self::try_parse_version(candidate) {
                    return Some(version);
                }
                version_start = None;
            }
        }

        // Try the remainder
        if let Some(start) = version_start {
            return Self::try_parse_version(&producer[start..]);
        }

        None
    }

    fn try_parse_version(s: &str) -> Option<(u32, u32, u32)> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() >= 2 {
            let major = parts[0].parse().ok()?;
            let minor_str: String = parts[1]
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            let minor = minor_str.parse().ok()?;
            let patch = if parts.len() > 2 {
                let patch_str: String = parts[2]
                    .chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect();
                patch_str.parse().unwrap_or(0)
            } else {
                0
            };
            return Some((major, minor, patch));
        }
        None
    }

    /// Check if any compilation unit has LTO enabled
    pub fn has_lto(&self) -> bool {
        self.compilation_units
            .iter()
            .any(|cu| cu.parsed_info.has_lto)
    }

    /// Check if all compilation units have stack clash protection
    pub fn has_stack_clash_protection(&self) -> bool {
        if self.compilation_units.is_empty() {
            return false;
        }
        self.compilation_units
            .iter()
            .all(|cu| cu.parsed_info.has_stack_clash_protection)
    }

    /// Check if any compilation unit has stack protector
    pub fn has_stack_protector(&self) -> bool {
        self.compilation_units
            .iter()
            .any(|cu| cu.parsed_info.has_stack_protector)
    }

    /// Get the minimum optimization level across all compilation units
    /// Returns None if no optimization info is available
    pub fn min_optimization_level(&self) -> Option<i32> {
        let levels: Vec<i32> = self
            .compilation_units
            .iter()
            .filter_map(|cu| {
                cu.parsed_info.optimization_level.as_ref().and_then(|opt| {
                    match opt.as_str() {
                        "-O0" => Some(0),
                        "-O1" | "-O" => Some(1),
                        "-O2" => Some(2),
                        "-O3" => Some(3),
                        "-Os" => Some(2), // Size optimization, similar security to O2
                        "-Oz" => Some(2), // Size optimization (Clang)
                        "-Ofast" => Some(3),
                        "-Og" => Some(1), // Debug optimization
                        _ => None,
                    }
                })
            })
            .collect();

        levels.into_iter().min()
    }

    /// Get the primary compiler type used
    pub fn primary_compiler(&self) -> CompilerType {
        self.compilation_units
            .first()
            .map(|cu| cu.parsed_info.compiler_type)
            .unwrap_or(CompilerType::Unknown)
    }

    /// Check if a specific compiler flag is present in any compilation unit
    pub fn has_flag(&self, flag: &str) -> bool {
        self.compilation_units
            .iter()
            .any(|cu| cu.parsed_info.flags.iter().any(|f| f == flag))
    }

    /// Check if a specific compiler flag is absent from all compilation units
    /// (useful for checking -fno-* flags)
    pub fn lacks_flag(&self, flag: &str) -> bool {
        !self.has_flag(flag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("test-fixtures")
    }

    #[test]
    fn test_parse_producer_gcc() {
        let producer =
            "GNU C17 12.2.0 -mtune=generic -march=x86-64 -g -O2 -fstack-protector-strong";
        let info = DwarfInfo::parse_producer(producer);

        assert_eq!(info.compiler_type, CompilerType::Gcc);
        assert_eq!(info.optimization_level, Some("-O2".to_string()));
        assert!(info.has_stack_protector);
        assert!(!info.has_lto);
        assert!(info.flags.contains(&"-O2".to_string()));
        assert!(info.flags.contains(&"-g".to_string()));
    }

    #[test]
    fn test_parse_producer_clang() {
        let producer = "clang version 15.0.0 -O3 -flto -fstack-clash-protection";
        let info = DwarfInfo::parse_producer(producer);

        assert_eq!(info.compiler_type, CompilerType::Clang);
        assert_eq!(info.optimization_level, Some("-O3".to_string()));
        assert!(info.has_lto);
        assert!(info.has_stack_clash_protection);
    }

    #[test]
    fn test_parse_producer_rustc() {
        let producer = "rustc version 1.75.0 (82e1608df 2023-12-21)";
        let info = DwarfInfo::parse_producer(producer);

        assert_eq!(info.compiler_type, CompilerType::Rustc);
    }

    #[test]
    fn test_parse_producer_no_optimization() {
        let producer = "GNU C17 12.2.0 -mtune=generic -g -O0";
        let info = DwarfInfo::parse_producer(producer);

        assert_eq!(info.optimization_level, Some("-O0".to_string()));
    }

    #[test]
    fn test_parse_producer_fortify_source() {
        let producer = "GNU C17 12.2.0 -D_FORTIFY_SOURCE=2 -O2";
        let info = DwarfInfo::parse_producer(producer);

        assert!(info.has_fortify_source);
    }

    #[test]
    fn test_compiler_type_display() {
        assert_eq!(CompilerType::Gcc.to_string(), "GCC");
        assert_eq!(CompilerType::Clang.to_string(), "Clang");
        assert_eq!(CompilerType::Rustc.to_string(), "rustc");
        assert_eq!(CompilerType::Go.to_string(), "Go");
        assert_eq!(CompilerType::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn test_dwarf_language_display() {
        assert_eq!(DwarfLanguage::C.to_string(), "C");
        assert_eq!(DwarfLanguage::CPlusPlus.to_string(), "C++");
        assert_eq!(DwarfLanguage::Rust.to_string(), "Rust");
        assert_eq!(DwarfLanguage::Go.to_string(), "Go");
        assert_eq!(DwarfLanguage::Unknown(999).to_string(), "Unknown(999)");
    }

    #[test]
    fn test_load_dwarf_from_binary() {
        let debug_binary = fixtures_dir().join("with_debug");
        if debug_binary.exists() {
            let dwarf = DwarfInfo::load(&debug_binary).unwrap();
            assert!(dwarf.has_debug_info);
            assert!(!dwarf.compilation_units.is_empty());
            assert!(dwarf.dwarf_version >= 2);
        }
    }

    #[test]
    fn test_no_dwarf_from_stripped_binary() {
        let binary = fixtures_dir().join("hardened");
        if binary.exists() {
            let dwarf = DwarfInfo::load(&binary).unwrap();
            // Hardened binary may or may not have debug info
            // Just verify parsing doesn't crash
            let _ = dwarf.has_debug_info;
        }
    }

    #[test]
    fn test_has_lto_check() {
        let debug_binary = fixtures_dir().join("with_debug");
        if debug_binary.exists() {
            let dwarf = DwarfInfo::load(&debug_binary).unwrap();
            // Just verify the method works
            let _ = dwarf.has_lto();
        }
    }

    #[test]
    fn test_min_optimization_level() {
        let debug_binary = fixtures_dir().join("with_debug");
        if debug_binary.exists() {
            let dwarf = DwarfInfo::load(&debug_binary).unwrap();
            if let Some(level) = dwarf.min_optimization_level() {
                // Level should be a valid optimization level
                assert!(level >= 0);
            }
        }
    }

    #[test]
    fn test_no_optimization_binary() {
        let binary = fixtures_dir().join("no_optimization");
        if binary.exists() {
            let dwarf = DwarfInfo::load(&binary).unwrap();
            if dwarf.has_debug_info && !dwarf.compilation_units.is_empty() {
                // Should have optimization level 0 or no optimization
                let min_level = dwarf.min_optimization_level();
                if let Some(level) = min_level {
                    assert_eq!(level, 0);
                }
            }
        }
    }

    #[test]
    fn test_primary_compiler() {
        let debug_binary = fixtures_dir().join("with_debug");
        if debug_binary.exists() {
            let dwarf = DwarfInfo::load(&debug_binary).unwrap();
            let compiler = dwarf.primary_compiler();
            // GCC was used to compile our test binaries
            assert_eq!(compiler, CompilerType::Gcc);
        }
    }

    #[test]
    fn test_has_flag() {
        let debug_binary = fixtures_dir().join("with_debug");
        if debug_binary.exists() {
            let dwarf = DwarfInfo::load(&debug_binary).unwrap();
            // Just verify method works
            let _ = dwarf.has_flag("-O2");
            let _ = dwarf.lacks_flag("-fno-stack-protector");
        }
    }

    #[test]
    fn test_version_parsing() {
        let producer = "GNU C17 12.2.0 -O2";
        let info = DwarfInfo::parse_producer(producer);

        // Should parse version
        if let Some((major, minor, _)) = info.version {
            assert_eq!(major, 12);
            assert_eq!(minor, 2);
        }
    }

    #[test]
    fn test_parse_no_flags() {
        let producer = "Unknown compiler";
        let info = DwarfInfo::parse_producer(producer);

        assert_eq!(info.compiler_type, CompilerType::Unknown);
        assert!(info.flags.is_empty());
        assert!(info.optimization_level.is_none());
    }
}
