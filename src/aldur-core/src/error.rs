//! Error types for Aldur

use thiserror::Error;

/// Result type alias for Aldur operations
pub type Result<T> = std::result::Result<T, AldurError>;

/// Errors that can occur during binary analysis
#[derive(Error, Debug)]
pub enum AldurError {
    /// Error loading a binary file
    #[error("Failed to load binary '{path}': {message}")]
    BinaryLoadError { path: String, message: String },

    /// Error parsing PE binary
    #[error("PE parse error: {0}")]
    PEParseError(String),

    /// Error parsing ELF binary
    #[error("ELF parse error: {0}")]
    ElfParseError(String),

    /// Error parsing Mach-O binary
    #[error("Mach-O parse error: {0}")]
    MachOParseError(String),

    /// Error loading PDB
    #[error("PDB load error for '{path}': {message}")]
    PdbLoadError { path: String, message: String },

    /// Error parsing DWARF debug info
    #[error("DWARF parse error: {0}")]
    DwarfParseError(String),

    /// Rule execution error
    #[error("Rule '{rule_id}' failed: {message}")]
    RuleError { rule_id: String, message: String },

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// File not found
    #[error("File not found: {0}")]
    FileNotFound(String),

    /// Invalid file format
    #[error("Invalid file format: {0}")]
    InvalidFormat(String),

    /// SARIF output error
    #[error("SARIF error: {0}")]
    SarifError(String),

    /// Generic error
    #[error("{0}")]
    Other(String),
}

impl AldurError {
    /// Create a binary load error
    pub fn binary_load(path: impl Into<String>, message: impl Into<String>) -> Self {
        AldurError::BinaryLoadError {
            path: path.into(),
            message: message.into(),
        }
    }

    /// Create a PDB load error
    pub fn pdb_load(path: impl Into<String>, message: impl Into<String>) -> Self {
        AldurError::PdbLoadError {
            path: path.into(),
            message: message.into(),
        }
    }

    /// Create a rule error
    pub fn rule(rule_id: impl Into<String>, message: impl Into<String>) -> Self {
        AldurError::RuleError {
            rule_id: rule_id.into(),
            message: message.into(),
        }
    }
}
