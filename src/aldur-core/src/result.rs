//! Analysis result types

use serde::{Deserialize, Serialize};

/// The kind of result from a rule
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ResultKind {
    /// The rule passed
    Pass,
    /// The rule failed
    Fail,
    /// The rule found an informational issue
    Informational,
    /// The rule is not applicable to this target
    NotApplicable,
    /// The result needs human review
    Review,
    /// The issue is open (not yet resolved)
    Open,
}

impl std::fmt::Display for ResultKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResultKind::Pass => write!(f, "pass"),
            ResultKind::Fail => write!(f, "fail"),
            ResultKind::Informational => write!(f, "informational"),
            ResultKind::NotApplicable => write!(f, "notApplicable"),
            ResultKind::Review => write!(f, "review"),
            ResultKind::Open => write!(f, "open"),
        }
    }
}

/// The severity level of a failure
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum FailureLevel {
    /// No failure
    None,
    /// Informational note
    Note,
    /// Warning
    Warning,
    /// Error
    Error,
}

impl Default for FailureLevel {
    fn default() -> Self {
        FailureLevel::Warning
    }
}

impl std::fmt::Display for FailureLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FailureLevel::None => write!(f, "none"),
            FailureLevel::Note => write!(f, "note"),
            FailureLevel::Warning => write!(f, "warning"),
            FailureLevel::Error => write!(f, "error"),
        }
    }
}

/// Result from a single rule execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleResult {
    /// The rule ID (e.g., "AD2008")
    pub rule_id: String,
    /// The kind of result
    pub kind: ResultKind,
    /// The failure level (for failures)
    pub level: FailureLevel,
    /// The message ID within the rule
    pub message_id: String,
    /// The formatted message
    pub message: String,
    /// The file path this result applies to
    pub target_path: String,
    /// Additional properties
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub properties: std::collections::HashMap<String, String>,
}

impl RuleResult {
    /// Create a passing result
    pub fn pass(
        rule_id: impl Into<String>,
        message_id: impl Into<String>,
        message: impl Into<String>,
        target_path: impl Into<String>,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            kind: ResultKind::Pass,
            level: FailureLevel::None,
            message_id: message_id.into(),
            message: message.into(),
            target_path: target_path.into(),
            properties: std::collections::HashMap::new(),
        }
    }

    /// Create a failure result
    pub fn fail(
        rule_id: impl Into<String>,
        level: FailureLevel,
        message_id: impl Into<String>,
        message: impl Into<String>,
        target_path: impl Into<String>,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            kind: ResultKind::Fail,
            level,
            message_id: message_id.into(),
            message: message.into(),
            target_path: target_path.into(),
            properties: std::collections::HashMap::new(),
        }
    }

    /// Create a not-applicable result
    pub fn not_applicable(
        rule_id: impl Into<String>,
        message_id: impl Into<String>,
        message: impl Into<String>,
        target_path: impl Into<String>,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            kind: ResultKind::NotApplicable,
            level: FailureLevel::None,
            message_id: message_id.into(),
            message: message.into(),
            target_path: target_path.into(),
            properties: std::collections::HashMap::new(),
        }
    }

    /// Add a property to the result
    pub fn with_property(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.properties.insert(key.into(), value.into());
        self
    }
}

/// Summary of analysis results
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// Total files analyzed
    pub files_analyzed: usize,
    /// Files that passed all rules
    pub files_passed: usize,
    /// Files with failures
    pub files_failed: usize,
    /// Files with warnings
    pub files_with_warnings: usize,
    /// Files skipped (invalid, not applicable, etc.)
    pub files_skipped: usize,
    /// Total rules executed
    pub rules_executed: usize,
    /// Results from individual rules
    pub results: Vec<RuleResult>,
    /// Runtime errors encountered
    pub runtime_errors: Vec<String>,
}

impl AnalysisResult {
    /// Create a new empty result
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a rule result
    pub fn add_result(&mut self, result: RuleResult) {
        self.results.push(result);
    }

    /// Add a runtime error
    pub fn add_runtime_error(&mut self, error: impl Into<String>) {
        self.runtime_errors.push(error.into());
    }

    /// Get count of errors
    pub fn error_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.kind == ResultKind::Fail && r.level == FailureLevel::Error)
            .count()
    }

    /// Get count of warnings
    pub fn warning_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.kind == ResultKind::Fail && r.level == FailureLevel::Warning)
            .count()
    }

    /// Check if there are any failures
    pub fn has_failures(&self) -> bool {
        self.results.iter().any(|r| r.kind == ResultKind::Fail)
    }

    /// Check if there are any errors
    pub fn has_errors(&self) -> bool {
        self.results.iter().any(|r| {
            r.kind == ResultKind::Fail && r.level == FailureLevel::Error
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_result_kind_display() {
        assert_eq!(format!("{}", ResultKind::Pass), "pass");
        assert_eq!(format!("{}", ResultKind::Fail), "fail");
        assert_eq!(format!("{}", ResultKind::NotApplicable), "notApplicable");
        assert_eq!(format!("{}", ResultKind::Informational), "informational");
        assert_eq!(format!("{}", ResultKind::Review), "review");
        assert_eq!(format!("{}", ResultKind::Open), "open");
    }

    #[test]
    fn test_failure_level_display() {
        assert_eq!(format!("{}", FailureLevel::None), "none");
        assert_eq!(format!("{}", FailureLevel::Note), "note");
        assert_eq!(format!("{}", FailureLevel::Warning), "warning");
        assert_eq!(format!("{}", FailureLevel::Error), "error");
    }

    #[test]
    fn test_failure_level_ordering() {
        assert!(FailureLevel::None < FailureLevel::Note);
        assert!(FailureLevel::Note < FailureLevel::Warning);
        assert!(FailureLevel::Warning < FailureLevel::Error);
    }

    #[test]
    fn test_failure_level_default() {
        assert_eq!(FailureLevel::default(), FailureLevel::Warning);
    }

    #[test]
    fn test_rule_result_pass() {
        let result = RuleResult::pass("AD2001", "Pass", "Image loads above 4GB", "/test/file.exe");
        assert_eq!(result.rule_id, "AD2001");
        assert_eq!(result.kind, ResultKind::Pass);
        assert_eq!(result.level, FailureLevel::None);
        assert_eq!(result.message_id, "Pass");
        assert_eq!(result.target_path, "/test/file.exe");
    }

    #[test]
    fn test_rule_result_fail() {
        let result = RuleResult::fail(
            "AD2001",
            FailureLevel::Error,
            "Error",
            "Image does not load above 4GB",
            "/test/file.exe",
        );
        assert_eq!(result.rule_id, "AD2001");
        assert_eq!(result.kind, ResultKind::Fail);
        assert_eq!(result.level, FailureLevel::Error);
    }

    #[test]
    fn test_rule_result_not_applicable() {
        let result = RuleResult::not_applicable(
            "AD2001",
            "NotApplicable",
            "Not a 64-bit binary",
            "/test/file.exe",
        );
        assert_eq!(result.kind, ResultKind::NotApplicable);
        assert_eq!(result.level, FailureLevel::None);
    }

    #[test]
    fn test_rule_result_with_property() {
        let result = RuleResult::pass("AD2001", "Pass", "OK", "/test/file.exe")
            .with_property("imageBase", "0x140000000");
        assert_eq!(
            result.properties.get("imageBase"),
            Some(&"0x140000000".to_string())
        );
    }

    #[test]
    fn test_analysis_result_counts() {
        let mut analysis = AnalysisResult::new();

        analysis.add_result(RuleResult::pass("AD2001", "Pass", "OK", "/file1.exe"));
        analysis.add_result(RuleResult::fail(
            "AD2008",
            FailureLevel::Error,
            "Error",
            "No CFG",
            "/file2.exe",
        ));
        analysis.add_result(RuleResult::fail(
            "AD2009",
            FailureLevel::Warning,
            "Warn",
            "No ASLR",
            "/file3.exe",
        ));

        assert_eq!(analysis.error_count(), 1);
        assert_eq!(analysis.warning_count(), 1);
        assert!(analysis.has_failures());
        assert!(analysis.has_errors());
    }

    #[test]
    fn test_analysis_result_no_errors() {
        let mut analysis = AnalysisResult::new();
        analysis.add_result(RuleResult::pass("AD2001", "Pass", "OK", "/file1.exe"));

        assert_eq!(analysis.error_count(), 0);
        assert_eq!(analysis.warning_count(), 0);
        assert!(!analysis.has_failures());
        assert!(!analysis.has_errors());
    }

    #[test]
    fn test_analysis_result_runtime_error() {
        let mut analysis = AnalysisResult::new();
        analysis.add_runtime_error("Failed to load binary");

        assert_eq!(analysis.runtime_errors.len(), 1);
        assert_eq!(analysis.runtime_errors[0], "Failed to load binary");
    }
}
