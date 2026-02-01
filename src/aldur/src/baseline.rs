//! Baseline comparison for SARIF results
//!
//! This module provides the ability to compare new analysis results against
//! a baseline SARIF file to:
//! - Suppress known issues
//! - Show only new findings
//! - Track security posture over time

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use aldur_core::{AnalysisResult, FailureLevel, ResultKind, RuleResult};

/// A fingerprint for uniquely identifying a result
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultFingerprint {
    /// The rule ID
    pub rule_id: String,
    /// The target file name (not full path for portability)
    pub target_name: String,
    /// The message ID within the rule
    pub message_id: String,
    /// Optional: hash of the message for more precise matching
    pub message_hash: Option<u64>,
}

impl ResultFingerprint {
    /// Create a fingerprint from a rule result
    pub fn from_result(result: &RuleResult) -> Self {
        // Extract just the filename from the path
        let target_name = Path::new(&result.target_path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| result.target_path.clone());

        // Simple hash of the message for more precise matching
        let message_hash = Some(Self::hash_message(&result.message));

        Self {
            rule_id: result.rule_id.clone(),
            target_name,
            message_id: result.message_id.clone(),
            message_hash,
        }
    }

    /// Simple hash function for message content
    fn hash_message(message: &str) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        message.hash(&mut hasher);
        hasher.finish()
    }
}

/// A baseline containing known issues
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Baseline {
    /// Version of the baseline format
    pub version: String,
    /// When the baseline was created
    pub created_at: String,
    /// Tool that created the baseline
    pub tool: String,
    /// Fingerprints of known issues
    pub known_issues: HashSet<ResultFingerprint>,
    /// Statistics from the baseline
    pub stats: BaselineStats,
}

/// Statistics from a baseline
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BaselineStats {
    /// Total results in baseline
    pub total_results: usize,
    /// Errors in baseline
    pub errors: usize,
    /// Warnings in baseline
    pub warnings: usize,
    /// Files in baseline
    pub files: usize,
}

impl Baseline {
    /// Create a new baseline from analysis results
    pub fn from_results(results: &AnalysisResult) -> Self {
        let mut known_issues = HashSet::new();

        for result in &results.results {
            // Only baseline failures (not passes or N/A)
            if result.kind == ResultKind::Fail {
                known_issues.insert(ResultFingerprint::from_result(result));
            }
        }

        let stats = BaselineStats {
            total_results: known_issues.len(),
            errors: results.error_count(),
            warnings: results.warning_count(),
            files: results.files_analyzed,
        };

        Self {
            version: "1.0".to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            tool: format!("Aldur {}", env!("CARGO_PKG_VERSION")),
            known_issues,
            stats,
        }
    }

    /// Load a baseline from a file (SARIF or JSON)
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read baseline file: {}", path.display()))?;

        // Try to parse as an Aldur baseline first
        if let Ok(baseline) = serde_json::from_str::<Self>(&content) {
            return Ok(baseline);
        }

        // Try to parse as SARIF and extract fingerprints
        Self::from_sarif(&content)
            .with_context(|| "Failed to parse baseline as SARIF or Aldur baseline format")
    }

    /// Parse a SARIF file and extract result fingerprints
    fn from_sarif(content: &str) -> Result<Self> {
        #[derive(Deserialize)]
        struct SarifLog {
            runs: Vec<SarifRun>,
        }

        #[derive(Deserialize)]
        struct SarifRun {
            results: Option<Vec<SarifResult>>,
        }

        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct SarifResult {
            rule_id: Option<String>,
            message: Option<SarifMessage>,
            locations: Option<Vec<SarifLocation>>,
            level: Option<String>,
        }

        #[derive(Deserialize)]
        struct SarifMessage {
            text: Option<String>,
            id: Option<String>,
        }

        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct SarifLocation {
            physical_location: Option<SarifPhysicalLocation>,
        }

        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct SarifPhysicalLocation {
            artifact_location: Option<SarifArtifactLocation>,
        }

        #[derive(Deserialize)]
        struct SarifArtifactLocation {
            uri: Option<String>,
        }

        let sarif: SarifLog = serde_json::from_str(content)?;
        let mut known_issues = HashSet::new();
        let mut errors = 0;
        let mut warnings = 0;
        let mut files = HashSet::new();

        for run in sarif.runs {
            if let Some(results) = run.results {
                for result in results {
                    let rule_id = result.rule_id.unwrap_or_default();
                    let message_id = result
                        .message
                        .as_ref()
                        .and_then(|m| m.id.clone())
                        .unwrap_or_else(|| "default".to_string());
                    let message_text = result
                        .message
                        .as_ref()
                        .and_then(|m| m.text.clone())
                        .unwrap_or_default();

                    let target_name = result
                        .locations
                        .as_ref()
                        .and_then(|l| l.first())
                        .and_then(|l| l.physical_location.as_ref())
                        .and_then(|p| p.artifact_location.as_ref())
                        .and_then(|a| a.uri.as_ref())
                        .map(|uri| {
                            Path::new(uri)
                                .file_name()
                                .map(|n| n.to_string_lossy().to_string())
                                .unwrap_or_else(|| uri.clone())
                        })
                        .unwrap_or_default();

                    if !target_name.is_empty() {
                        files.insert(target_name.clone());
                    }

                    // Count by level
                    match result.level.as_deref() {
                        Some("error") => errors += 1,
                        Some("warning") => warnings += 1,
                        _ => {}
                    }

                    if !rule_id.is_empty() {
                        known_issues.insert(ResultFingerprint {
                            rule_id,
                            target_name,
                            message_id,
                            message_hash: Some(ResultFingerprint::hash_message(&message_text)),
                        });
                    }
                }
            }
        }

        let total_results = known_issues.len();
        let files_count = files.len();

        Ok(Self {
            version: "1.0".to_string(),
            created_at: String::new(),
            tool: "imported from SARIF".to_string(),
            known_issues,
            stats: BaselineStats {
                total_results,
                errors,
                warnings,
                files: files_count,
            },
        })
    }

    /// Save baseline to a file
    pub fn save(&self, path: &Path) -> Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Check if a result is in the baseline
    pub fn contains(&self, result: &RuleResult) -> bool {
        let fingerprint = ResultFingerprint::from_result(result);

        // Try exact match first
        if self.known_issues.contains(&fingerprint) {
            return true;
        }

        // Try match without message hash (for slight message variations)
        let relaxed_fingerprint = ResultFingerprint {
            message_hash: None,
            ..fingerprint
        };

        self.known_issues.iter().any(|ki| {
            ki.rule_id == relaxed_fingerprint.rule_id
                && ki.target_name == relaxed_fingerprint.target_name
                && ki.message_id == relaxed_fingerprint.message_id
        })
    }
}

/// Result of comparing against a baseline
#[derive(Debug, Clone, Default)]
pub struct BaselineComparison {
    /// New issues not in the baseline
    pub new_issues: Vec<RuleResult>,
    /// Issues that were in the baseline and still exist
    pub existing_issues: Vec<RuleResult>,
    /// Issues in the baseline that no longer exist (fixed)
    pub fixed_issues: Vec<ResultFingerprint>,
    /// All passing results (unchanged)
    pub passing_results: Vec<RuleResult>,
}

impl BaselineComparison {
    /// Compare analysis results against a baseline
    pub fn compare(results: &AnalysisResult, baseline: &Baseline) -> Self {
        let mut comparison = Self::default();
        let mut seen_fingerprints = HashSet::new();

        for result in &results.results {
            if result.kind == ResultKind::Fail {
                let fingerprint = ResultFingerprint::from_result(result);
                seen_fingerprints.insert(fingerprint.clone());

                if baseline.contains(result) {
                    comparison.existing_issues.push(result.clone());
                } else {
                    comparison.new_issues.push(result.clone());
                }
            } else if result.kind == ResultKind::Pass {
                comparison.passing_results.push(result.clone());
            }
        }

        // Find fixed issues (in baseline but not in current results)
        for known in &baseline.known_issues {
            let is_fixed = !seen_fingerprints.iter().any(|seen| {
                seen.rule_id == known.rule_id
                    && seen.target_name == known.target_name
                    && seen.message_id == known.message_id
            });
            if is_fixed {
                comparison.fixed_issues.push(known.clone());
            }
        }

        comparison
    }

    /// Get count of new errors
    #[allow(dead_code)]
    pub fn new_error_count(&self) -> usize {
        self.new_issues
            .iter()
            .filter(|r| r.level == FailureLevel::Error)
            .count()
    }

    /// Get count of new warnings
    #[allow(dead_code)]
    pub fn new_warning_count(&self) -> usize {
        self.new_issues
            .iter()
            .filter(|r| r.level == FailureLevel::Warning)
            .count()
    }

    /// Check if there are any new issues
    #[allow(dead_code)]
    pub fn has_new_issues(&self) -> bool {
        !self.new_issues.is_empty()
    }

    /// Check if there are any new errors
    pub fn has_new_errors(&self) -> bool {
        self.new_issues
            .iter()
            .any(|r| r.level == FailureLevel::Error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_creation() {
        let result = RuleResult::fail(
            "AD3001",
            FailureLevel::Error,
            "fail",
            "PIE not enabled",
            "/path/to/binary",
        );

        let fingerprint = ResultFingerprint::from_result(&result);
        assert_eq!(fingerprint.rule_id, "AD3001");
        assert_eq!(fingerprint.target_name, "binary");
        assert_eq!(fingerprint.message_id, "fail");
    }

    #[test]
    fn test_baseline_contains() {
        let result = RuleResult::fail(
            "AD3001",
            FailureLevel::Error,
            "fail",
            "PIE not enabled",
            "/path/to/binary",
        );

        let mut analysis = AnalysisResult::new();
        analysis.add_result(result.clone());

        let baseline = Baseline::from_results(&analysis);
        assert!(baseline.contains(&result));
    }

    #[test]
    fn test_baseline_comparison() {
        // Create baseline with one issue
        let baseline_result = RuleResult::fail(
            "AD3001",
            FailureLevel::Error,
            "fail",
            "PIE not enabled",
            "/path/to/old_binary",
        );
        let mut baseline_analysis = AnalysisResult::new();
        baseline_analysis.add_result(baseline_result);
        let baseline = Baseline::from_results(&baseline_analysis);

        // Create new results with a different issue
        let new_result = RuleResult::fail(
            "AD3002",
            FailureLevel::Error,
            "fail",
            "Stack executable",
            "/path/to/new_binary",
        );
        let mut new_analysis = AnalysisResult::new();
        new_analysis.add_result(new_result);

        let comparison = BaselineComparison::compare(&new_analysis, &baseline);
        assert_eq!(comparison.new_issues.len(), 1);
        assert_eq!(comparison.fixed_issues.len(), 1);
        assert_eq!(comparison.existing_issues.len(), 0);
    }
}
