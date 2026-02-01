//! GitHub Actions output formatter
//!
//! Formats analysis results using GitHub Actions workflow commands for:
//! - Inline annotations in PR diffs (::error::, ::warning::, ::notice::)
//! - Grouped output for better log readability (::group::, ::endgroup::)
//!
//! See: https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions

use std::collections::HashMap;
use std::io::Write;

use aldur_core::{AnalysisResult, FailureLevel, ResultKind, Rule, RuleCategory, RuleResult};

/// GitHub Actions formatter for analysis results
pub struct GitHubActionsFormatter<'a> {
    /// Whether to show passing rules
    show_passed: bool,
    /// Rules for looking up metadata
    rules: &'a [Box<dyn Rule>],
}

impl<'a> GitHubActionsFormatter<'a> {
    /// Create a new GitHub Actions formatter
    pub fn new(rules: &'a [Box<dyn Rule>]) -> Self {
        Self {
            show_passed: false,
            rules,
        }
    }

    /// Set whether to show passing rules
    pub fn with_show_passed(mut self, show_passed: bool) -> Self {
        self.show_passed = show_passed;
        self
    }

    /// Format analysis results to a string
    pub fn format(&self, results: &AnalysisResult) -> String {
        let mut output = Vec::new();
        self.write(&mut output, results).unwrap();
        String::from_utf8(output).unwrap()
    }

    /// Write formatted results to a writer
    pub fn write<W: Write>(&self, writer: &mut W, results: &AnalysisResult) -> std::io::Result<()> {
        // Build rule lookup map
        let rule_map: HashMap<&str, &dyn Rule> = self
            .rules
            .iter()
            .map(|r| (r.id(), r.as_ref()))
            .collect();

        // Group results by file
        let grouped = self.group_results(&results.results);

        // Write results grouped by file
        for (file_path, file_results) in grouped {
            // Start a group for this file
            writeln!(writer, "::group::📁 {}", file_path)?;

            for result in file_results {
                self.write_result(writer, result, &rule_map)?;
            }

            writeln!(writer, "::endgroup::")?;
        }

        // Write summary
        self.write_summary(writer, results)?;

        Ok(())
    }

    fn group_results<'b>(&self, results: &'b [RuleResult]) -> Vec<(String, Vec<&'b RuleResult>)> {
        let mut by_file: HashMap<String, Vec<&RuleResult>> = HashMap::new();

        for result in results {
            // Skip passes unless show_passed is enabled
            if result.kind == ResultKind::Pass && !self.show_passed {
                continue;
            }
            // Skip not-applicable
            if result.kind == ResultKind::NotApplicable {
                continue;
            }
            by_file
                .entry(result.target_path.clone())
                .or_default()
                .push(result);
        }

        // Sort by file path
        let mut grouped: Vec<_> = by_file.into_iter().collect();
        grouped.sort_by(|a, b| a.0.cmp(&b.0));

        // Sort results within each file by severity then rule ID
        for (_, results) in &mut grouped {
            results.sort_by(|a, b| {
                let severity_a = Self::severity_order(&a.kind, &a.level);
                let severity_b = Self::severity_order(&b.kind, &b.level);
                severity_a.cmp(&severity_b).then(a.rule_id.cmp(&b.rule_id))
            });
        }

        grouped
    }

    fn severity_order(kind: &ResultKind, level: &FailureLevel) -> u8 {
        match (kind, level) {
            (ResultKind::Fail, FailureLevel::Error) => 0,
            (ResultKind::Fail, FailureLevel::Warning) => 1,
            (ResultKind::Fail, FailureLevel::Note) => 2,
            (ResultKind::Pass, _) => 3,
            _ => 4,
        }
    }

    fn write_result<W: Write>(
        &self,
        writer: &mut W,
        result: &RuleResult,
        rule_map: &HashMap<&str, &dyn Rule>,
    ) -> std::io::Result<()> {
        // Get rule metadata
        let rule = rule_map.get(result.rule_id.as_str());
        let rule_name = rule.map(|r| r.name()).unwrap_or("");

        let category = rule
            .map(|r| r.descriptor().category)
            .unwrap_or(RuleCategory::Security);

        // Get fix hint if available
        let fix_hint = rule.and_then(|r| r.descriptor().fix_hint.as_ref());

        // Format the title
        let title = format!("{} {} ({})", result.rule_id, rule_name, category);

        // Escape the message for workflow commands
        let message = Self::escape_workflow_data(&result.message);

        // Build full message with fix hint if available
        let full_message = if let Some(hint) = fix_hint {
            format!("{} | Fix: {}", message, Self::escape_workflow_data(hint))
        } else {
            message
        };

        // Get the file path (try to make it relative for better display)
        let file = Self::normalize_path(&result.target_path);

        match (&result.kind, &result.level) {
            (ResultKind::Fail, FailureLevel::Error) => {
                writeln!(
                    writer,
                    "::error file={},title={}::{}",
                    file, title, full_message
                )?;
            }
            (ResultKind::Fail, FailureLevel::Warning) => {
                writeln!(
                    writer,
                    "::warning file={},title={}::{}",
                    file, title, full_message
                )?;
            }
            (ResultKind::Fail, FailureLevel::Note) | (ResultKind::Fail, FailureLevel::None) => {
                writeln!(
                    writer,
                    "::notice file={},title={}::{}",
                    file, title, full_message
                )?;
            }
            (ResultKind::Pass, _) => {
                // For passes, just print a regular message (no annotation)
                writeln!(writer, "✓ {} {}: {}", result.rule_id, rule_name, result.message)?;
            }
            _ => {
                // Other result kinds (informational, review, etc.)
                writeln!(
                    writer,
                    "::notice file={},title={}::{}",
                    file, title, full_message
                )?;
            }
        }

        Ok(())
    }

    fn write_summary<W: Write>(&self, writer: &mut W, results: &AnalysisResult) -> std::io::Result<()> {
        let errors = results.error_count();
        let warnings = results.warning_count();
        let passed = results
            .results
            .iter()
            .filter(|r| r.kind == ResultKind::Pass)
            .count();

        writeln!(writer)?;
        writeln!(writer, "::group::📊 Summary")?;

        if errors > 0 {
            writeln!(writer, "❌ Errors: {}", errors)?;
        }
        if warnings > 0 {
            writeln!(writer, "⚠️  Warnings: {}", warnings)?;
        }
        if passed > 0 && self.show_passed {
            writeln!(writer, "✅ Passed: {}", passed)?;
        }

        writeln!(writer, "📁 Files analyzed: {}", results.files_analyzed)?;

        // Congratulate if everything passed
        if errors == 0 && warnings == 0 && results.files_analyzed > 0 {
            writeln!(writer, "🎉 Congratulations! All security checks passed.")?;
        }

        writeln!(writer, "::endgroup::")?;

        // Set output for the action
        if std::env::var("GITHUB_OUTPUT").is_ok() {
            // These would be written to GITHUB_OUTPUT file in the action
            // For now, we'll use the legacy set-output command format for visibility
            writeln!(writer)?;
            writeln!(writer, "::set-output name=errors::{}", errors)?;
            writeln!(writer, "::set-output name=warnings::{}", warnings)?;
            writeln!(writer, "::set-output name=passed::{}", passed)?;
        }

        Ok(())
    }

    /// Escape special characters for GitHub Actions workflow commands
    /// See: https://github.com/actions/toolkit/blob/main/packages/core/src/command.ts
    fn escape_workflow_data(s: &str) -> String {
        s.replace('%', "%25")
            .replace('\r', "%0D")
            .replace('\n', "%0A")
    }

    /// Normalize path for display (try to make relative)
    fn normalize_path(path: &str) -> String {
        // If running in GitHub Actions, try to make path relative to workspace
        if let Ok(workspace) = std::env::var("GITHUB_WORKSPACE") {
            if let Some(relative) = path.strip_prefix(&workspace) {
                return relative.trim_start_matches(['/', '\\']).to_string();
            }
        }

        // If path is absolute (starts with / or drive letter), get just the filename
        let is_absolute = path.starts_with('/')
            || path.starts_with('\\')
            || (path.len() >= 2 && path.chars().nth(1) == Some(':'));

        if is_absolute {
            if let Some(pos) = path.rfind(['/', '\\']) {
                return path[pos + 1..].to_string();
            }
        }

        // Return relative paths as-is
        path.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_workflow_data() {
        assert_eq!(
            GitHubActionsFormatter::escape_workflow_data("line1\nline2"),
            "line1%0Aline2"
        );
        assert_eq!(
            GitHubActionsFormatter::escape_workflow_data("100% complete"),
            "100%25 complete"
        );
    }

    #[test]
    fn test_normalize_path() {
        assert_eq!(
            GitHubActionsFormatter::normalize_path("/path/to/file.exe"),
            "file.exe"
        );
        assert_eq!(
            GitHubActionsFormatter::normalize_path("relative/path.dll"),
            "relative/path.dll"
        );
    }

    #[test]
    fn test_severity_order() {
        assert!(
            GitHubActionsFormatter::severity_order(&ResultKind::Fail, &FailureLevel::Error)
                < GitHubActionsFormatter::severity_order(&ResultKind::Fail, &FailureLevel::Warning)
        );
        assert!(
            GitHubActionsFormatter::severity_order(&ResultKind::Fail, &FailureLevel::Warning)
                < GitHubActionsFormatter::severity_order(&ResultKind::Pass, &FailureLevel::None)
        );
    }
}
