//! Analysis context for managing state during binary analysis

use crate::binary::Binary;
use crate::result::RuleResult;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Configuration for analysis
#[derive(Debug, Clone, Default)]
pub struct AnalysisConfig {
    /// Symbol path for PDB lookup (Windows)
    pub symbol_path: Option<String>,
    /// Local symbol directories
    pub local_symbol_directories: Option<String>,
    /// Whether to trace PDB loading
    pub trace_pdb_loads: bool,
    /// Whether to ignore PDB load errors
    pub ignore_pdb_load_error: bool,
    /// Whether to ignore PE load errors
    pub ignore_pe_load_error: bool,
    /// Whether to include WiX binaries
    pub include_wix_binaries: bool,
    /// Maximum file size in kilobytes (0 = unlimited)
    pub max_file_size_kb: u64,
    /// Custom policy properties
    pub properties: HashMap<String, String>,
}

/// Context for a single binary analysis
pub struct AnalysisContext {
    /// Path to the current target binary
    target_path: PathBuf,
    /// The parsed binary (lazily loaded)
    binary: Option<Arc<dyn Binary>>,
    /// Analysis configuration
    pub config: AnalysisConfig,
    /// Results collected during analysis
    results: Vec<RuleResult>,
    /// Runtime errors encountered
    runtime_errors: Vec<String>,
    /// Whether analysis is complete
    pub analysis_complete: bool,
}

impl AnalysisContext {
    /// Create a new analysis context for a target binary
    pub fn new(target_path: impl Into<PathBuf>, config: AnalysisConfig) -> Self {
        Self {
            target_path: target_path.into(),
            binary: None,
            config,
            results: Vec::new(),
            runtime_errors: Vec::new(),
            analysis_complete: false,
        }
    }

    /// Get the path to the target binary
    pub fn target_path(&self) -> &Path {
        &self.target_path
    }

    /// Get the file name of the target binary
    pub fn file_name(&self) -> String {
        self.target_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string()
    }

    /// Set the parsed binary
    pub fn set_binary(&mut self, binary: Arc<dyn Binary>) {
        self.binary = Some(binary);
    }

    /// Get the parsed binary, if available
    pub fn binary(&self) -> Option<&Arc<dyn Binary>> {
        self.binary.as_ref()
    }

    /// Add a rule result
    pub fn add_result(&mut self, result: RuleResult) {
        self.results.push(result);
    }

    /// Get all rule results
    pub fn results(&self) -> &[RuleResult] {
        &self.results
    }

    /// Take all results, consuming them
    pub fn take_results(&mut self) -> Vec<RuleResult> {
        std::mem::take(&mut self.results)
    }

    /// Add a runtime error
    pub fn add_runtime_error(&mut self, error: impl Into<String>) {
        self.runtime_errors.push(error.into());
    }

    /// Get runtime errors
    pub fn runtime_errors(&self) -> &[String] {
        &self.runtime_errors
    }

    /// Check if there are any runtime errors
    pub fn has_runtime_errors(&self) -> bool {
        !self.runtime_errors.is_empty()
    }

    /// Get a configuration property
    pub fn get_property(&self, key: &str) -> Option<&str> {
        self.config.properties.get(key).map(|s| s.as_str())
    }

    /// Set a configuration property
    pub fn set_property(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.config.properties.insert(key.into(), value.into());
    }
}

impl std::fmt::Debug for AnalysisContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnalysisContext")
            .field("target_path", &self.target_path)
            .field("has_binary", &self.binary.is_some())
            .field("result_count", &self.results.len())
            .field("error_count", &self.runtime_errors.len())
            .finish()
    }
}
