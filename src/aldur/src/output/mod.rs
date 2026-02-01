//! Output formatters for analysis results
//!
//! This module provides different output formats for displaying analysis results.
//! - SARIF: Structured JSON format (default, for tooling integration)
//! - Text: Human-readable text with ANSI colors for terminal display
//! - GitHub Actions: Workflow commands for inline PR annotations

mod github_actions;
mod text;

pub use github_actions::GitHubActionsFormatter;
pub use text::TextFormatter;

use std::str::FromStr;

/// Output format selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    /// SARIF JSON format (default)
    #[default]
    Sarif,
    /// Plain text without colors
    Text,
    /// Text with ANSI color codes
    TextColor,
    /// GitHub Actions workflow commands (annotations)
    GitHubActions,
}

impl FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "sarif" | "json" => Ok(OutputFormat::Sarif),
            "text" | "plain" => Ok(OutputFormat::Text),
            "text-color" | "color" | "ansi" => Ok(OutputFormat::TextColor),
            "github-actions" | "gha" | "actions" => Ok(OutputFormat::GitHubActions),
            _ => Err(format!(
                "Unknown output format '{}'. Valid options: sarif, text, text-color, github-actions",
                s
            )),
        }
    }
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Sarif => write!(f, "sarif"),
            OutputFormat::Text => write!(f, "text"),
            OutputFormat::TextColor => write!(f, "text-color"),
            OutputFormat::GitHubActions => write!(f, "github-actions"),
        }
    }
}
