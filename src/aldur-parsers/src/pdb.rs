//! PDB (Program Database) file parser
//!
//! Parses Windows PDB files using the `pdb` crate for cross-platform support.
//! Extracts:
//! - Compilation units (compilands)
//! - Compiler information
//! - Command line arguments
//! - Source files

use aldur_core::{AldurError, Result};
use pdb::{FallibleIterator, PDB};
use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};

/// Compiler information from a compiland
#[derive(Debug, Clone, Default)]
pub struct CompilerInfo {
    /// Compiler name
    pub name: String,
    /// Front-end version (major, minor, build, qfe)
    pub frontend_version: (u16, u16, u16, u16),
    /// Back-end version (major, minor, build, qfe)
    pub backend_version: (u16, u16, u16, u16),
    /// Language
    pub language: String,
    /// Whether /GS (security checks) is enabled
    pub security_checks: Option<bool>,
    /// Whether /sdl is enabled
    pub sdl_checks: Option<bool>,
}

/// Compiland (object module) information
#[derive(Debug, Clone)]
pub struct CompilandInfo {
    /// Name of the compiland (usually the object file path)
    pub name: String,
    /// Library name (for static libraries)
    pub library_name: Option<String>,
    /// Compiler information
    pub compiler: CompilerInfo,
    /// Command line used to compile
    pub command_line: Option<String>,
    /// Source files
    pub source_files: Vec<String>,
    /// Whether stack protection (/GS) is enabled
    pub has_security_checks: Option<bool>,
}

/// Source file with checksum information
#[derive(Debug, Clone)]
pub struct SourceFileInfo {
    /// File name
    pub name: String,
    /// Checksum algorithm (MD5, SHA-1, SHA-256)
    pub checksum_algorithm: Option<String>,
    /// Checksum value
    pub checksum: Vec<u8>,
}

/// PDB file parser
pub struct PdbFile {
    /// Path to the PDB file
    #[allow(dead_code)]
    path: PathBuf,
    /// Compilands found in the PDB
    pub compilands: Vec<CompilandInfo>,
    /// Source files with checksums
    pub source_files: Vec<SourceFileInfo>,
    /// Whether the PDB is stripped
    pub is_stripped: bool,
    /// PDB GUID
    pub guid: Option<String>,
    /// PDB age
    pub age: u32,
    /// Whether the PDB loaded successfully
    pub valid: bool,
    /// Load error message
    pub load_error: Option<String>,
}

impl PdbFile {
    /// Load a PDB file
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = File::open(&path).map_err(|e| AldurError::pdb_load(path.display().to_string(), e.to_string()))?;

        Self::parse(path, file)
    }

    fn parse(path: PathBuf, file: File) -> Result<Self> {
        let mut pdb = PDB::open(file).map_err(|e| AldurError::pdb_load(path.display().to_string(), e.to_string()))?;

        let mut result = PdbFile {
            path,
            compilands: Vec::new(),
            source_files: Vec::new(),
            is_stripped: false,
            guid: None,
            age: 0,
            valid: true,
            load_error: None,
        };

        // Get PDB info
        if let Ok(info) = pdb.pdb_information() {
            result.guid = Some(format!("{:?}", info.guid));
            result.age = info.age;
        }

        // Check for debug information
        let debug_info = match pdb.debug_information() {
            Ok(info) => info,
            Err(e) => {
                result.load_error = Some(format!("Failed to read debug info: {}", e));
                result.is_stripped = true;
                return Ok(result);
            }
        };

        // Parse modules (compilands)
        let mut modules = match debug_info.modules() {
            Ok(m) => m,
            Err(e) => {
                result.load_error = Some(format!("Failed to read modules: {}", e));
                return Ok(result);
            }
        };

        let string_table = pdb.string_table().ok();

        while let Ok(Some(module)) = modules.next() {
            let mut compiland = CompilandInfo {
                name: module.module_name().to_string(),
                library_name: Some(module.object_file_name().to_string()),
                compiler: CompilerInfo::default(),
                command_line: None,
                source_files: Vec::new(),
                has_security_checks: None,
            };

            // Try to get module info for symbol parsing
            if let Ok(Some(module_info)) = pdb.module_info(&module) {
                // Parse symbols to find compiler info
                if let Ok(symbols) = module_info.symbols() {
                    let mut symbol_iter = symbols;
                    while let Ok(Some(symbol)) = symbol_iter.next() {
                        // Parse symbol data
                        if let Ok(pdb::SymbolData::CompileFlags(compile_info)) = symbol.parse() {
                            compiland.compiler.frontend_version = (
                                compile_info.frontend_version.major,
                                compile_info.frontend_version.minor,
                                compile_info.frontend_version.build,
                                compile_info.frontend_version.qfe.unwrap_or(0),
                            );
                            compiland.compiler.backend_version = (
                                compile_info.backend_version.major,
                                compile_info.backend_version.minor,
                                compile_info.backend_version.build,
                                compile_info.backend_version.qfe.unwrap_or(0),
                            );
                            compiland.compiler.language = format!("{:?}", compile_info.language);
                            // Extract compiler name/version string from PDB
                            compiland.compiler.name = compile_info.version_string.to_string().into_owned();
                            // Extract security check flags
                            compiland.compiler.security_checks = Some(compile_info.flags.security_checks);
                            compiland.compiler.sdl_checks = Some(compile_info.flags.sdl);
                            compiland.has_security_checks = Some(compile_info.flags.security_checks);
                        }
                    }
                }

                // Parse line information for source files
                if let Some(ref st) = string_table {
                    if let Ok(line_program) = module_info.line_program() {
                        let mut files = line_program.files();
                        while let Ok(Some(file_info)) = files.next() {
                            if let Ok(name_raw) = st.get(file_info.name) {
                                let name: String = name_raw.to_string().into_owned();
                                compiland.source_files.push(name.clone());

                                // Extract checksum info
                                let (algo, checksum_bytes) = match &file_info.checksum {
                                    pdb::FileChecksum::None => (None, Vec::new()),
                                    pdb::FileChecksum::Md5(bytes) => (Some("MD5"), bytes.to_vec()),
                                    pdb::FileChecksum::Sha1(bytes) => (Some("SHA-1"), bytes.to_vec()),
                                    pdb::FileChecksum::Sha256(bytes) => (Some("SHA-256"), bytes.to_vec()),
                                };

                                result.source_files.push(SourceFileInfo {
                                    name: name.to_string(),
                                    checksum_algorithm: algo.map(|s| s.to_string()),
                                    checksum: checksum_bytes,
                                });
                            }
                        }
                    }
                }
            }

            result.compilands.push(compiland);
        }

        Ok(result)
    }

    /// Check if any compiland uses an insecure checksum algorithm (MD5 or SHA-1)
    pub fn has_insecure_source_hashing(&self) -> bool {
        self.source_files.iter().any(|f| {
            matches!(
                f.checksum_algorithm.as_deref(),
                Some("MD5") | Some("SHA-1")
            )
        })
    }

    /// Get compilands with insecure source hashing
    pub fn insecure_hash_compilands(&self) -> Vec<&SourceFileInfo> {
        self.source_files
            .iter()
            .filter(|f| {
                matches!(
                    f.checksum_algorithm.as_deref(),
                    Some("MD5") | Some("SHA-1")
                )
            })
            .collect()
    }

    /// Check if any compiland has the /GS flag disabled
    pub fn has_disabled_security_checks(&self) -> Vec<&CompilandInfo> {
        self.compilands
            .iter()
            .filter(|c| c.has_security_checks == Some(false))
            .collect()
    }

    /// Parse command line arguments from compilands
    pub fn parse_command_lines(&self) -> HashMap<&str, Vec<&str>> {
        let mut result = HashMap::new();
        for compiland in &self.compilands {
            if let Some(ref cmd) = compiland.command_line {
                let args: Vec<&str> = cmd.split_whitespace().collect();
                result.insert(compiland.name.as_str(), args);
            }
        }
        result
    }

    /// Get the compiler version as a string
    pub fn compiler_version_string(&self) -> Option<String> {
        self.compilands.first().map(|c| {
            format!(
                "{}.{}.{}.{}",
                c.compiler.backend_version.0,
                c.compiler.backend_version.1,
                c.compiler.backend_version.2,
                c.compiler.backend_version.3
            )
        })
    }

    /// Check if compiled with a minimum compiler version
    pub fn meets_minimum_version(&self, major: u16, minor: u16, build: u16) -> bool {
        self.compilands.iter().all(|c| {
            let v = c.compiler.backend_version;
            v.0 > major || (v.0 == major && v.1 > minor) || (v.0 == major && v.1 == minor && v.2 >= build)
        })
    }
}
