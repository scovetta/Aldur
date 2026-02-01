//! Binary trait and types for representing parsed binaries

use std::path::{Path, PathBuf};

/// The format of a binary file
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinaryFormat {
    /// Windows Portable Executable
    PE,
    /// Executable and Linkable Format (Linux/Unix)
    ELF,
    /// Mach Object (macOS/iOS)
    MachO,
    /// Unknown format
    Unknown,
}

impl std::fmt::Display for BinaryFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BinaryFormat::PE => write!(f, "PE"),
            BinaryFormat::ELF => write!(f, "ELF"),
            BinaryFormat::MachO => write!(f, "Mach-O"),
            BinaryFormat::Unknown => write!(f, "Unknown"),
        }
    }
}

/// The type of binary (executable, library, etc.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinaryType {
    /// Executable binary
    Executable,
    /// Dynamic library (DLL, SO, dylib)
    DynamicLibrary,
    /// Static library
    StaticLibrary,
    /// Object file
    Object,
    /// Core dump
    Core,
    /// Driver or kernel module
    Driver,
    /// Unknown type
    Unknown,
}

impl std::fmt::Display for BinaryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BinaryType::Executable => write!(f, "Executable"),
            BinaryType::DynamicLibrary => write!(f, "Dynamic Library"),
            BinaryType::StaticLibrary => write!(f, "Static Library"),
            BinaryType::Object => write!(f, "Object"),
            BinaryType::Core => write!(f, "Core"),
            BinaryType::Driver => write!(f, "Driver"),
            BinaryType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Trait representing a parsed binary file
///
/// This is the core abstraction for all binary types (PE, ELF, Mach-O).
/// Implementations provide access to binary metadata and parsed structures.
pub trait Binary: Send + Sync {
    /// Returns the path to the binary file
    fn path(&self) -> &Path;

    /// Returns the binary format
    fn format(&self) -> BinaryFormat;

    /// Returns the binary type
    fn binary_type(&self) -> BinaryType;

    /// Returns whether this is a 64-bit binary
    fn is_64_bit(&self) -> bool;

    /// Returns whether the binary was successfully parsed
    fn is_valid(&self) -> bool;

    /// Returns the error that occurred during loading, if any
    fn load_error(&self) -> Option<&str>;

    /// Returns the file name without the directory path
    fn file_name(&self) -> &str {
        self.path()
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
    }

    /// Returns self as Any for downcasting
    fn as_any(&self) -> &dyn std::any::Any;
}

/// Wrapper for binary files that provides shared ownership
#[derive(Debug)]
pub struct BinaryTarget {
    /// Path to the binary file
    pub path: PathBuf,
    /// Whether the binary is valid for analysis
    pub valid: bool,
    /// Error message if loading failed
    pub error: Option<String>,
}

impl BinaryTarget {
    /// Create a new binary target
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            valid: true,
            error: None,
        }
    }

    /// Create an invalid target with an error
    pub fn invalid(path: impl Into<PathBuf>, error: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            valid: false,
            error: Some(error.into()),
        }
    }
}
