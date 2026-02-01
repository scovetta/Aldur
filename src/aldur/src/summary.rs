//! Multi-target summary report generation
//!
//! When scanning many binaries, this module produces aggregate statistics:
//! - Pass/fail counts per rule
//! - Worst-offending binaries
//! - Coverage statistics (e.g., "95% of binaries have PIE enabled")

use std::collections::{BTreeMap, HashMap};
use std::io::Write;

use aldur_core::{AnalysisResult, FailureLevel, ResultKind, RuleResult};

/// Summary statistics for a single rule across all targets
#[derive(Debug, Clone, Default)]
pub struct RuleSummary {
    /// Rule ID
    pub rule_id: String,
    /// Rule name
    pub rule_name: String,
    /// Number of passes
    pub pass_count: usize,
    /// Number of failures
    pub fail_count: usize,
    /// Number of warnings
    pub warning_count: usize,
    /// Number of errors
    pub error_count: usize,
    /// Number of not-applicable results
    pub na_count: usize,
    /// Targets that failed this rule
    pub failed_targets: Vec<String>,
}

impl RuleSummary {
    /// Calculate pass rate as a percentage
    pub fn pass_rate(&self) -> f64 {
        let total = self.pass_count + self.fail_count;
        if total == 0 {
            100.0
        } else {
            (self.pass_count as f64 / total as f64) * 100.0
        }
    }

    /// Get the total number of applicable targets
    pub fn applicable_count(&self) -> usize {
        self.pass_count + self.fail_count
    }
}

/// Summary for a single target (binary)
#[derive(Debug, Clone, Default)]
pub struct TargetSummary {
    /// Target path/name
    pub target: String,
    /// Number of errors
    pub error_count: usize,
    /// Number of warnings
    pub warning_count: usize,
    /// Number of passing rules
    pub pass_count: usize,
    /// List of failed rule IDs
    pub failed_rules: Vec<String>,
    /// Security score (0-100)
    pub security_score: u8,
}

impl TargetSummary {
    /// Calculate a simple security score based on pass rate
    pub fn calculate_score(&mut self) {
        let total = self.pass_count + self.error_count + self.warning_count;
        if total == 0 {
            self.security_score = 100;
        } else {
            // Errors count double against the score
            let penalty = (self.error_count * 2 + self.warning_count) as f64;
            let score = ((total as f64 - penalty) / total as f64) * 100.0;
            self.security_score = score.clamp(0.0, 100.0) as u8;
        }
    }
}

/// Aggregate summary across all targets
#[derive(Debug, Clone, Default)]
pub struct MultiTargetSummary {
    /// Total number of targets analyzed
    pub total_targets: usize,
    /// Targets with no errors
    pub clean_targets: usize,
    /// Targets with errors
    pub targets_with_errors: usize,
    /// Targets with warnings only
    pub targets_with_warnings_only: usize,
    /// Per-rule summaries
    pub rule_summaries: BTreeMap<String, RuleSummary>,
    /// Per-target summaries
    pub target_summaries: Vec<TargetSummary>,
    /// Overall security score (0-100)
    pub overall_score: u8,
    /// Top issues by frequency
    pub top_issues: Vec<(String, usize)>,
}

impl MultiTargetSummary {
    /// Build a summary from analysis results
    pub fn from_results(results: &AnalysisResult, rules: &[Box<dyn aldur_core::Rule>]) -> Self {
        let mut summary = Self::default();

        // Build rule name lookup
        let rule_names: HashMap<String, String> = rules
            .iter()
            .map(|r| {
                let desc = r.descriptor();
                (desc.id.clone(), desc.name.clone())
            })
            .collect();

        // Group results by target
        let mut target_results: HashMap<String, Vec<&RuleResult>> = HashMap::new();
        for result in &results.results {
            target_results
                .entry(result.target_path.clone())
                .or_default()
                .push(result);
        }

        summary.total_targets = target_results.len();

        // Process each target
        for (target, results) in &target_results {
            let mut target_summary = TargetSummary {
                target: Self::extract_filename(target),
                ..Default::default()
            };

            for result in results {
                // Update rule summary
                let rule_summary = summary
                    .rule_summaries
                    .entry(result.rule_id.clone())
                    .or_insert_with(|| RuleSummary {
                        rule_id: result.rule_id.clone(),
                        rule_name: rule_names
                            .get(&result.rule_id)
                            .cloned()
                            .unwrap_or_else(|| result.rule_id.clone()),
                        ..Default::default()
                    });

                match result.kind {
                    ResultKind::Pass => {
                        rule_summary.pass_count += 1;
                        target_summary.pass_count += 1;
                    }
                    ResultKind::Fail => {
                        rule_summary.fail_count += 1;
                        rule_summary
                            .failed_targets
                            .push(Self::extract_filename(target));
                        target_summary.failed_rules.push(result.rule_id.clone());

                        match result.level {
                            FailureLevel::Error => {
                                rule_summary.error_count += 1;
                                target_summary.error_count += 1;
                            }
                            FailureLevel::Warning => {
                                rule_summary.warning_count += 1;
                                target_summary.warning_count += 1;
                            }
                            _ => {}
                        }
                    }
                    ResultKind::NotApplicable => {
                        rule_summary.na_count += 1;
                    }
                    _ => {}
                }
            }

            // Categorize target
            if target_summary.error_count > 0 {
                summary.targets_with_errors += 1;
            } else if target_summary.warning_count > 0 {
                summary.targets_with_warnings_only += 1;
            } else {
                summary.clean_targets += 1;
            }

            target_summary.calculate_score();
            summary.target_summaries.push(target_summary);
        }

        // Sort targets by error count (worst first)
        summary.target_summaries.sort_by(|a, b| {
            b.error_count
                .cmp(&a.error_count)
                .then(b.warning_count.cmp(&a.warning_count))
        });

        // Calculate top issues
        let mut issue_counts: Vec<(String, usize)> = summary
            .rule_summaries
            .iter()
            .filter(|(_, s)| s.fail_count > 0)
            .map(|(id, s)| (id.clone(), s.fail_count))
            .collect();
        issue_counts.sort_by(|a, b| b.1.cmp(&a.1));
        summary.top_issues = issue_counts.into_iter().take(10).collect();

        // Calculate overall score
        if summary.total_targets > 0 {
            let total_score: u32 = summary
                .target_summaries
                .iter()
                .map(|t| t.security_score as u32)
                .sum();
            summary.overall_score = (total_score / summary.total_targets as u32) as u8;
        }

        summary
    }

    /// Extract filename from path
    fn extract_filename(path: &str) -> String {
        std::path::Path::new(path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| path.to_string())
    }

    /// Write summary to a writer (text format)
    pub fn write_text<W: Write>(&self, writer: &mut W, use_colors: bool) -> std::io::Result<()> {
        let red = if use_colors { "\x1b[31m" } else { "" };
        let yellow = if use_colors { "\x1b[33m" } else { "" };
        let green = if use_colors { "\x1b[32m" } else { "" };
        let bold = if use_colors { "\x1b[1m" } else { "" };
        let reset = if use_colors { "\x1b[0m" } else { "" };

        writeln!(writer)?;
        writeln!(
            writer,
            "{}╔══════════════════════════════════════════════════════════════╗{}",
            bold, reset
        )?;
        writeln!(
            writer,
            "{}║             MULTI-TARGET SECURITY SUMMARY                    ║{}",
            bold, reset
        )?;
        writeln!(
            writer,
            "{}╚══════════════════════════════════════════════════════════════╝{}",
            bold, reset
        )?;
        writeln!(writer)?;

        // Overall statistics
        writeln!(writer, "{}📊 Overall Statistics{}", bold, reset)?;
        writeln!(writer, "─────────────────────────────────────────")?;
        writeln!(writer, "  Total binaries analyzed: {}", self.total_targets)?;
        writeln!(
            writer,
            "  {}✓ Clean (no issues):{} {}",
            green, reset, self.clean_targets
        )?;
        writeln!(
            writer,
            "  {}⚠ Warnings only:{} {}",
            yellow, reset, self.targets_with_warnings_only
        )?;
        writeln!(
            writer,
            "  {}✗ With errors:{} {}",
            red, reset, self.targets_with_errors
        )?;
        writeln!(
            writer,
            "  Overall security score: {}{}%{}",
            if self.overall_score >= 80 {
                green
            } else if self.overall_score >= 60 {
                yellow
            } else {
                red
            },
            self.overall_score,
            reset
        )?;
        writeln!(writer)?;

        // Top issues
        if !self.top_issues.is_empty() {
            writeln!(writer, "{}🔥 Top Issues by Frequency{}", bold, reset)?;
            writeln!(writer, "─────────────────────────────────────────")?;
            for (i, (rule_id, count)) in self.top_issues.iter().enumerate().take(5) {
                let rule_name = self
                    .rule_summaries
                    .get(rule_id)
                    .map(|s| s.rule_name.as_str())
                    .unwrap_or(rule_id);
                writeln!(
                    writer,
                    "  {}. {} ({}) - {} binaries",
                    i + 1,
                    rule_id,
                    rule_name,
                    count
                )?;
            }
            writeln!(writer)?;
        }

        // Worst offenders
        let worst: Vec<_> = self
            .target_summaries
            .iter()
            .filter(|t| t.error_count > 0)
            .take(5)
            .collect();

        if !worst.is_empty() {
            writeln!(
                writer,
                "{}🚨 Binaries Needing Most Attention{}",
                bold, reset
            )?;
            writeln!(writer, "─────────────────────────────────────────")?;
            for target in worst {
                writeln!(
                    writer,
                    "  {}• {}{}: {}{}E{} / {}{}W{} (score: {}%)",
                    red,
                    target.target,
                    reset,
                    red,
                    target.error_count,
                    reset,
                    yellow,
                    target.warning_count,
                    reset,
                    target.security_score
                )?;
            }
            writeln!(writer)?;
        }

        // Rule coverage
        writeln!(writer, "{}📈 Security Feature Coverage{}", bold, reset)?;
        writeln!(writer, "─────────────────────────────────────────")?;

        // Sort by pass rate (lowest first to show areas needing improvement)
        let mut sorted_rules: Vec<_> = self.rule_summaries.values().collect();
        sorted_rules.sort_by(|a, b| a.pass_rate().partial_cmp(&b.pass_rate()).unwrap());

        // Find longest rule name for alignment
        let max_name_len = sorted_rules
            .iter()
            .filter(|r| r.applicable_count() > 0)
            .map(|r| r.rule_name.len())
            .max()
            .unwrap_or(20)
            .min(30);

        for rule in sorted_rules.iter().take(10) {
            if rule.applicable_count() == 0 {
                continue;
            }
            let rate = rule.pass_rate();
            let bar_len = (rate / 5.0) as usize; // 20 chars = 100%
            let bar = "█".repeat(bar_len) + &"░".repeat(20 - bar_len);
            let color = if rate >= 90.0 {
                green
            } else if rate >= 70.0 {
                yellow
            } else {
                red
            };

            writeln!(
                writer,
                "  [{}{}{}] {:>5.1}% {:width$} {} ({}/{})",
                color,
                bar,
                reset,
                rate,
                rule.rule_name,
                rule.rule_id,
                rule.pass_count,
                rule.applicable_count(),
                width = max_name_len
            )?;
        }
        writeln!(writer)?;

        Ok(())
    }

    /// Format as Markdown
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();

        md.push_str("# Multi-Target Security Summary\n\n");

        // Overall statistics
        md.push_str("## 📊 Overall Statistics\n\n");
        md.push_str("| Metric | Value |\n");
        md.push_str("|--------|-------|\n");
        md.push_str(&format!("| Total binaries | {} |\n", self.total_targets));
        md.push_str(&format!("| ✅ Clean | {} |\n", self.clean_targets));
        md.push_str(&format!(
            "| ⚠️ Warnings only | {} |\n",
            self.targets_with_warnings_only
        ));
        md.push_str(&format!(
            "| ❌ With errors | {} |\n",
            self.targets_with_errors
        ));
        md.push_str(&format!("| Security Score | {}% |\n\n", self.overall_score));

        // Top issues
        if !self.top_issues.is_empty() {
            md.push_str("## 🔥 Top Issues\n\n");
            md.push_str("| Rule | Name | Count |\n");
            md.push_str("|------|------|-------|\n");
            for (rule_id, count) in &self.top_issues {
                let rule_name = self
                    .rule_summaries
                    .get(rule_id)
                    .map(|s| s.rule_name.as_str())
                    .unwrap_or(rule_id);
                md.push_str(&format!("| {} | {} | {} |\n", rule_id, rule_name, count));
            }
            md.push('\n');
        }

        // Coverage table
        md.push_str("## 📈 Security Feature Coverage\n\n");
        md.push_str("| Rule | Name | Pass Rate | Pass/Total |\n");
        md.push_str("|------|------|-----------|------------|\n");

        let mut sorted_rules: Vec<_> = self.rule_summaries.values().collect();
        sorted_rules.sort_by(|a, b| a.pass_rate().partial_cmp(&b.pass_rate()).unwrap());

        for rule in sorted_rules {
            if rule.applicable_count() == 0 {
                continue;
            }
            let emoji = if rule.pass_rate() >= 90.0 {
                "🟢"
            } else if rule.pass_rate() >= 70.0 {
                "🟡"
            } else {
                "🔴"
            };
            md.push_str(&format!(
                "| {} | {} | {} {:.1}% | {}/{} |\n",
                rule.rule_id,
                rule.rule_name,
                emoji,
                rule.pass_rate(),
                rule.pass_count,
                rule.applicable_count()
            ));
        }

        md
    }

    /// Format for GitHub Actions step summary
    #[allow(dead_code)]
    pub fn to_github_summary(&self) -> String {
        self.to_markdown()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_summary_score() {
        let mut summary = TargetSummary {
            target: "test".to_string(),
            error_count: 1,
            warning_count: 2,
            pass_count: 10,
            ..Default::default()
        };
        summary.calculate_score();
        // 10 pass, 1 error (counts as 2), 2 warnings = 13 total, 4 penalty
        // (13 - 4) / 13 * 100 = 69%
        assert!(summary.security_score > 60 && summary.security_score < 80);
    }

    #[test]
    fn test_rule_summary_pass_rate() {
        let summary = RuleSummary {
            pass_count: 8,
            fail_count: 2,
            ..Default::default()
        };
        assert!((summary.pass_rate() - 80.0).abs() < 0.01);
    }
}
