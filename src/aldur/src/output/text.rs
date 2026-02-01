//! Text output formatter with ANSI color support
//!
//! Formats analysis results in a human-readable format, grouped by:
//! 1. File path
//! 2. Rule category (Security, Correctness, etc.)
//! 3. Individual rules

use std::collections::HashMap;
use std::io::Write;

use colored::{ColoredString, Colorize};

use aldur_core::{AnalysisResult, FailureLevel, ResultKind, Rule, RuleCategory, RuleResult};

/// Text formatter for analysis results
pub struct TextFormatter<'a> {
    /// Whether to use ANSI colors
    use_colors: bool,
    /// Whether to show passing rules
    show_passed: bool,
    /// Rules for looking up metadata
    rules: &'a [Box<dyn Rule>],
}

impl<'a> TextFormatter<'a> {
    /// Create a new text formatter
    pub fn new(rules: &'a [Box<dyn Rule>]) -> Self {
        Self {
            use_colors: true,
            show_passed: false,
            rules,
        }
    }

    /// Set whether to use ANSI colors
    pub fn with_colors(mut self, use_colors: bool) -> Self {
        self.use_colors = use_colors;
        self
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
        // Set color override based on configuration
        if !self.use_colors {
            colored::control::set_override(false);
        }

        // Build rule lookup map for category info
        let rule_map: HashMap<&str, &dyn Rule> = self
            .rules
            .iter()
            .map(|r| (r.id(), r.as_ref()))
            .collect();

        // Group results: file -> category -> results
        let grouped = self.group_results(&results.results, &rule_map);

        // Write header
        self.write_header(writer, results)?;

        // Write grouped results
        let has_findings = !grouped.is_empty();
        for (file_path, categories) in grouped {
            self.write_file_section(writer, &file_path, &categories, &rule_map)?;
        }

        // Write summary
        self.write_summary(writer, results, has_findings)?;

        // Reset color override
        if !self.use_colors {
            colored::control::unset_override();
        }

        Ok(())
    }

    fn group_results<'b>(
        &self,
        results: &'b [RuleResult],
        rule_map: &HashMap<&str, &dyn Rule>,
    ) -> Vec<(String, HashMap<RuleCategory, Vec<&'b RuleResult>>)> {
        // First, group by file path
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

        // Then group each file's results by category
        let mut grouped: Vec<(String, HashMap<RuleCategory, Vec<&RuleResult>>)> = by_file
            .into_iter()
            .map(|(path, results)| {
                let mut by_category: HashMap<RuleCategory, Vec<&RuleResult>> = HashMap::new();
                for result in results {
                    let category = rule_map
                        .get(result.rule_id.as_str())
                        .map(|r| r.descriptor().category)
                        .unwrap_or(RuleCategory::Security);
                    by_category.entry(category).or_default().push(result);
                }
                (path, by_category)
            })
            .collect();

        // Sort files alphabetically
        grouped.sort_by(|a, b| a.0.cmp(&b.0));

        grouped
    }

    fn write_header<W: Write>(&self, writer: &mut W, _results: &AnalysisResult) -> std::io::Result<()> {
        writeln!(writer)?;
        writeln!(
            writer,
            "{}",
            self.style("Aldur Analysis Results", |s| s.bold().cyan())
        )?;
        let separator = "═".repeat(60);
        writeln!(
            writer,
            "{}",
            self.style(&separator, |s| s.dimmed())
        )?;
        writeln!(writer)?;
        Ok(())
    }

    fn write_file_section<W: Write>(
        &self,
        writer: &mut W,
        file_path: &str,
        categories: &HashMap<RuleCategory, Vec<&RuleResult>>,
        rule_map: &HashMap<&str, &dyn Rule>,
    ) -> std::io::Result<()> {
        // File header
        writeln!(
            writer,
            "{} {}",
            self.style("📁", |s| s.normal()),
            self.style(file_path, |s| s.bold().white())
        )?;

        // Sort categories by importance (Security first)
        let mut cats: Vec<_> = categories.keys().collect();
        cats.sort_by_key(|c| match c {
            RuleCategory::Security => 0,
            RuleCategory::Correctness => 1,
            RuleCategory::Performance => 2,
            RuleCategory::Maintainability => 3,
            RuleCategory::Reporting => 4,
        });

        for category in cats {
            let results = &categories[category];
            if results.is_empty() {
                continue;
            }

            // Category header
            let category_icon = match category {
                RuleCategory::Security => "🔒",
                RuleCategory::Correctness => "✓",
                RuleCategory::Performance => "⚡",
                RuleCategory::Maintainability => "🔧",
                RuleCategory::Reporting => "📊",
            };

            writeln!(
                writer,
                "  {} {}",
                category_icon,
                self.style(category.as_str(), |s| s.bold())
            )?;

            // Sort results by rule ID
            let mut sorted_results: Vec<_> = results.iter().collect();
            sorted_results.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));

            for result in sorted_results {
                self.write_result(writer, result, rule_map)?;
            }
        }

        writeln!(writer)?;
        Ok(())
    }

    fn write_result<W: Write>(
        &self,
        writer: &mut W,
        result: &RuleResult,
        rule_map: &HashMap<&str, &dyn Rule>,
    ) -> std::io::Result<()> {
        let (icon, rule_style): (&str, fn(&str) -> ColoredString) = match (&result.kind, &result.level) {
            (ResultKind::Pass, _) => ("✓", |s| s.green()),
            (ResultKind::Fail, FailureLevel::Error) => ("✗", |s| s.red().bold()),
            (ResultKind::Fail, FailureLevel::Warning) => ("⚠", |s| s.yellow()),
            (ResultKind::Fail, FailureLevel::Note) => ("ℹ", |s| s.blue()),
            _ => ("•", |s| s.normal()),
        };

        // Get rule name
        let rule_name = rule_map
            .get(result.rule_id.as_str())
            .map(|r| r.name())
            .unwrap_or("");

        // Write rule line
        writeln!(
            writer,
            "    {} {} {}",
            self.style(icon, rule_style),
            self.style(&result.rule_id, rule_style),
            self.style(rule_name, |s| s.dimmed())
        )?;

        // Write fix hint for failures
        if result.kind == ResultKind::Fail {
            if let Some(hint) = self.get_fix_hint(result, rule_map) {
                writeln!(
                    writer,
                    "      {} {}",
                    self.style("→", |s| s.dimmed()),
                    self.style(&hint, |s| s.italic())
                )?;
            }
        }

        Ok(())
    }

    fn get_fix_hint(&self, result: &RuleResult, rule_map: &HashMap<&str, &dyn Rule>) -> Option<String> {
        let rule = rule_map.get(result.rule_id.as_str())?;
        let descriptor = rule.descriptor();

        // First, check for an explicit fix_hint (preferred)
        if let Some(hint) = &descriptor.fix_hint {
            return Some(hint.clone());
        }

        // Fall back to extracting a compact fix hint from full_description
        // Look for common patterns like "compile with", "enable", "use", etc.
        let desc = &descriptor.full_description;

        // Look for compiler flag patterns
        if let Some(hint) = Self::extract_compiler_flag_hint(desc) {
            return Some(hint);
        }

        // Look for "To resolve" or "To fix" patterns
        if let Some(hint) = Self::extract_resolution_hint(desc) {
            return Some(hint);
        }

        // Fall back to using the error message template if available
        if let Some(error_msg) = descriptor.messages.get("Error") {
            if let Some(hint) = Self::extract_compiler_flag_hint(error_msg) {
                return Some(hint);
            }
        }

        // Last resort: provide the help URI
        Some(format!("See {}", descriptor.help_uri))
    }

    fn extract_compiler_flag_hint(text: &str) -> Option<String> {
        // Look for patterns like "compile with -flag" or "/flag"
        let patterns = [
            "compile with ",
            "Compile with ",
            "link with ",
            "Link with ",
            "use the ",
            "Use the ",
            "enable ",
            "Enable ",
            "add ",
            "Add ",
        ];

        for pattern in &patterns {
            if let Some(pos) = text.find(pattern) {
                let start = pos;
                // Find the end of the sentence
                let remaining = &text[start..];
                let end = remaining
                    .find(['.', '\n'])
                    .unwrap_or(remaining.len())
                    .min(120); // Cap at 120 chars

                let hint = remaining[..end].trim();
                if !hint.is_empty() {
                    // Capitalize first letter
                    let mut chars = hint.chars();
                    let first = chars.next().unwrap().to_uppercase();
                    return Some(format!("{}{}", first, chars.collect::<String>()));
                }
            }
        }

        // Look for compiler flags directly (e.g., -fstack-protector, /GUARD:CF)
        let flag_pattern = regex_lite_find_flag(text);
        if let Some(flag) = flag_pattern {
            return Some(format!("Compile/link with {}", flag));
        }

        None
    }

    fn extract_resolution_hint(text: &str) -> Option<String> {
        let patterns = ["To resolve", "To fix", "Resolution:", "Fix:"];

        for pattern in &patterns {
            if let Some(pos) = text.find(pattern) {
                let start = pos + pattern.len();
                let remaining = &text[start..];
                // Skip leading punctuation and whitespace
                let remaining = remaining.trim_start_matches(|c: char| matches!(c, ':' | ',') || c.is_whitespace());

                let end = remaining
                    .find(['.', '\n'])
                    .unwrap_or(remaining.len())
                    .min(120);

                let hint = remaining[..end].trim();
                if !hint.is_empty() {
                    return Some(hint.to_string());
                }
            }
        }

        None
    }

    fn write_summary<W: Write>(&self, writer: &mut W, results: &AnalysisResult, has_findings: bool) -> std::io::Result<()> {
        // Only show separator if there were findings displayed above
        if has_findings {
            let separator = "─".repeat(60);
            writeln!(
                writer,
                "{}",
                self.style(&separator, |s| s.dimmed())
            )?;
        }

        let error_count = results.error_count();
        let warning_count = results.warning_count();

        let error_str = if error_count > 0 {
            self.style(&format!("{} errors", error_count), |s| s.red().bold())
        } else {
            self.style("0 errors", |s| s.green())
        };

        let warning_str = if warning_count > 0 {
            self.style(&format!("{} warnings", warning_count), |s| s.yellow())
        } else {
            self.style("0 warnings", |s| s.green())
        };

        writeln!(
            writer,
            "Summary: {} files analyzed, {}, {}",
            results.files_analyzed,
            error_str,
            warning_str
        )?;

        // Congratulate the user if everything passed
        if error_count == 0 && warning_count == 0 && results.files_analyzed > 0 {
            writeln!(
                writer,
                "{}",
                self.style("🎉 Congratulations! All security checks passed.", |s| s.green().bold())
            )?;
        }

        if !results.runtime_errors.is_empty() {
            writeln!(
                writer,
                "{}",
                self.style(
                    &format!("Runtime errors: {}", results.runtime_errors.len()),
                    |s| s.red()
                )
            )?;
        }

        writeln!(writer)?;
        Ok(())
    }

    /// Apply styling if colors are enabled
    fn style<F>(&self, text: &str, styler: F) -> ColoredString
    where
        F: FnOnce(&str) -> ColoredString,
    {
        if self.use_colors {
            styler(text)
        } else {
            text.normal()
        }
    }
}

/// Simple flag extraction without full regex dependency
fn regex_lite_find_flag(text: &str) -> Option<String> {
    // Look for Unix-style flags (-flag or --flag)
    for word in text.split_whitespace() {
        let word = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '-' && c != '/');
        if (word.starts_with('-') || word.starts_with('/')) && word.len() > 1 {
            // Skip common non-flag patterns
            if word == "-" || word == "--" {
                continue;
            }
            return Some(word.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_compiler_flag_hint() {
        let text = "Compile with -fstack-protector-strong to enable stack protection.";
        let hint = TextFormatter::extract_compiler_flag_hint(text);
        assert!(hint.is_some());
        assert!(hint.unwrap().contains("-fstack-protector"));
    }

    #[test]
    fn test_extract_resolution_hint() {
        let text = "This is a security issue. To resolve: enable CFG in your linker settings.";
        let hint = TextFormatter::extract_resolution_hint(text);
        assert!(hint.is_some());
        assert!(hint.unwrap().contains("CFG"));
    }

    #[test]
    fn test_regex_lite_find_flag() {
        assert_eq!(regex_lite_find_flag("use -O2 flag"), Some("-O2".to_string()));
        assert_eq!(regex_lite_find_flag("use /GUARD:CF"), Some("/GUARD:CF".to_string()));
        assert_eq!(regex_lite_find_flag("no flags here"), None);
    }
}
