//! Configuration file handling

use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Configuration for Aldur
#[allow(dead_code)]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    /// Rule configurations
    #[serde(default)]
    pub rules: HashMap<String, RuleConfig>,

    /// Global settings
    #[serde(default)]
    pub settings: Settings,
}

/// Configuration for a single rule
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    /// Whether the rule is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Severity level override
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,

    /// Rule-specific parameters
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub parameters: HashMap<String, serde_json::Value>,
}

impl Default for RuleConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            level: None,
            parameters: HashMap::new(),
        }
    }
}

/// Global settings
#[allow(dead_code)]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Settings {
    /// Maximum file size in KB (0 = unlimited)
    #[serde(default)]
    pub max_file_size_kb: u64,

    /// Symbol path for PDB lookup
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol_path: Option<String>,

    /// Local symbol directories
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_symbol_directories: Option<String>,

    /// Ignore PDB load errors
    #[serde(default)]
    pub ignore_pdb_load_error: bool,

    /// Include WiX binaries
    #[serde(default)]
    pub include_wix_binaries: bool,
}

#[allow(dead_code)]
fn default_true() -> bool {
    true
}

#[allow(dead_code)]
impl Config {
    /// Load configuration from a file
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;

        if path.extension().map(|e| e == "json").unwrap_or(false) {
            Ok(serde_json::from_str(&content)?)
        } else {
            // Try JSON first, then YAML-like (basic)
            serde_json::from_str(&content).map_err(Into::into)
        }
    }

    /// Check if a rule is enabled
    pub fn is_rule_enabled(&self, rule_id: &str) -> bool {
        self.rules
            .get(rule_id)
            .map(|r| r.enabled)
            .unwrap_or(true)
    }

    /// Get rule level override
    pub fn rule_level(&self, rule_id: &str) -> Option<&str> {
        self.rules
            .get(rule_id)
            .and_then(|r| r.level.as_deref())
    }
}
