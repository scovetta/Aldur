//! Rule trait and types for security checks

use crate::context::AnalysisContext;
use crate::result::{FailureLevel, RuleResult};

/// Whether a rule can analyze a given target
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnalysisApplicability {
    /// The rule is applicable to this target
    ApplicableToSpecifiedTarget,
    /// The rule is not applicable to this target
    NotApplicableToSpecifiedTarget,
    /// The target is not valid for analysis
    NotApplicableDueToMissingTarget,
}

/// Category of a rule - what aspect of the binary it checks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleCategory {
    /// Security rules check for security mitigations and vulnerabilities
    Security,
    /// Correctness rules check for proper binary construction
    Correctness,
    /// Performance rules check for optimization settings
    Performance,
    /// Maintainability rules check for debugging and maintainability features
    Maintainability,
    /// Reporting rules produce informational output without pass/fail
    Reporting,
}

impl RuleCategory {
    /// Get the display name for the category
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleCategory::Security => "Security",
            RuleCategory::Correctness => "Correctness",
            RuleCategory::Performance => "Performance",
            RuleCategory::Maintainability => "Maintainability",
            RuleCategory::Reporting => "Reporting",
        }
    }
}

impl std::fmt::Display for RuleCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Descriptor for a rule, containing its metadata
#[derive(Debug, Clone)]
pub struct RuleDescriptor {
    /// Rule ID (e.g., "AD2008")
    pub id: String,
    /// Rule name (e.g., "EnableControlFlowGuard")
    pub name: String,
    /// Rule category
    pub category: RuleCategory,
    /// Short description
    pub short_description: String,
    /// Full description with remediation guidance
    pub full_description: String,
    /// Help URI
    pub help_uri: String,
    /// Default failure level
    pub default_level: FailureLevel,
    /// Message strings by ID
    pub messages: std::collections::HashMap<String, String>,
    /// Tags for profile-based filtering (e.g., "critical", "memory-safety", "intel-only")
    pub tags: Vec<String>,
    /// Explicit fix hint for remediation (e.g., "Compile with -fstack-protector-strong")
    /// If None, formatters will attempt to extract hints from full_description or messages
    pub fix_hint: Option<String>,
}

impl RuleDescriptor {
    /// Create a new rule descriptor with default category (Security)
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        let id = id.into();
        let name = name.into();
        Self {
            help_uri: format!(
                "https://github.com/scovetta/Aldur/blob/main/docs/rules/{}.{}.md",
                id, name
            ),
            id,
            name,
            category: RuleCategory::Security,
            short_description: String::new(),
            full_description: String::new(),
            default_level: FailureLevel::Warning,
            messages: std::collections::HashMap::new(),
            tags: Vec::new(),
            fix_hint: None,
        }
    }

    /// Set the rule category
    pub fn with_category(mut self, category: RuleCategory) -> Self {
        self.category = category;
        self
    }

    /// Add tags for profile-based filtering
    pub fn with_tags(mut self, tags: &[&str]) -> Self {
        self.tags.extend(tags.iter().map(|s| s.to_string()));
        self
    }

    /// Check if the rule has a specific tag
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t.eq_ignore_ascii_case(tag))
    }

    /// Set the short description
    pub fn with_short_description(mut self, desc: impl Into<String>) -> Self {
        self.short_description = desc.into();
        self
    }

    /// Set the full description
    pub fn with_full_description(mut self, desc: impl Into<String>) -> Self {
        self.full_description = desc.into();
        self
    }

    /// Set an explicit fix hint for remediation
    ///
    /// This provides a concise, actionable hint for how to fix the issue.
    /// Examples: "Compile with -fstack-protector-strong", "Link with -z now"
    ///
    /// If not set, formatters will attempt to extract hints from full_description.
    pub fn with_fix_hint(mut self, hint: impl Into<String>) -> Self {
        self.fix_hint = Some(hint.into());
        self
    }

    /// Set the default failure level
    pub fn with_default_level(mut self, level: FailureLevel) -> Self {
        self.default_level = level;
        self
    }

    /// Add a message
    pub fn with_message(mut self, id: impl Into<String>, message: impl Into<String>) -> Self {
        self.messages.insert(id.into(), message.into());
        self
    }

    /// Format a message with arguments
    pub fn format_message(&self, message_id: &str, args: &[&str]) -> String {
        if let Some(template) = self.messages.get(message_id) {
            let mut result = template.clone();
            for (i, arg) in args.iter().enumerate() {
                result = result.replace(&format!("{{{}}}", i), arg);
            }
            result
        } else {
            format!("Unknown message ID: {}", message_id)
        }
    }
}

/// Trait for implementing security rules
///
/// Rules check binaries for security issues and produce results.
pub trait Rule: Send + Sync {
    /// Get the rule descriptor
    fn descriptor(&self) -> &RuleDescriptor;

    /// Get the rule ID
    fn id(&self) -> &str {
        &self.descriptor().id
    }

    /// Get the rule name
    fn name(&self) -> &str {
        &self.descriptor().name
    }

    /// Initialize the rule (called once before analysis begins)
    fn initialize(&mut self) -> crate::Result<()> {
        Ok(())
    }

    /// Check if the rule can analyze the given target
    fn can_analyze(&self, context: &AnalysisContext) -> (AnalysisApplicability, Option<String>);

    /// Analyze the target and produce results
    fn analyze(&self, context: &mut AnalysisContext);

    /// Log a passing result
    fn log_pass(&self, context: &mut AnalysisContext, message_id: &str, args: &[&str]) {
        let message = self.descriptor().format_message(message_id, args);
        context.add_result(RuleResult::pass(
            self.id(),
            message_id,
            message,
            context.file_name(),
        ));
    }

    /// Log a failure result
    fn log_fail(
        &self,
        context: &mut AnalysisContext,
        level: FailureLevel,
        message_id: &str,
        args: &[&str],
    ) {
        let message = self.descriptor().format_message(message_id, args);
        context.add_result(RuleResult::fail(
            self.id(),
            level,
            message_id,
            message,
            context.file_name(),
        ));
    }

    /// Log a not-applicable result
    fn log_not_applicable(&self, context: &mut AnalysisContext, message_id: &str, args: &[&str]) {
        let message = self.descriptor().format_message(message_id, args);
        context.add_result(RuleResult::not_applicable(
            self.id(),
            message_id,
            message,
            context.file_name(),
        ));
    }
}

/// Macro to help define rule IDs
#[macro_export]
macro_rules! rule_ids {
    ($($name:ident = $value:expr),* $(,)?) => {
        $(
            pub const $name: &str = $value;
        )*
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_descriptor_with_fix_hint() {
        let desc = RuleDescriptor::new("AD9999", "TestRule")
            .with_short_description("Test description")
            .with_fix_hint("Compile with -ftest-flag");

        assert_eq!(desc.id, "AD9999");
        assert_eq!(desc.name, "TestRule");
        assert_eq!(desc.fix_hint, Some("Compile with -ftest-flag".to_string()));
    }

    #[test]
    fn test_rule_descriptor_without_fix_hint() {
        let desc =
            RuleDescriptor::new("AD9999", "TestRule").with_short_description("Test description");

        assert_eq!(desc.fix_hint, None);
    }

    #[test]
    fn test_fix_hint_builder_chain() {
        let desc = RuleDescriptor::new("AD9999", "TestRule")
            .with_category(RuleCategory::Security)
            .with_short_description("Short desc")
            .with_full_description("Full description with details")
            .with_fix_hint("Link with -Wl,-z,now")
            .with_default_level(FailureLevel::Error)
            .with_tags(&["critical", "memory-safety"]);

        assert_eq!(desc.fix_hint, Some("Link with -Wl,-z,now".to_string()));
        assert_eq!(desc.tags, vec!["critical", "memory-safety"]);
        assert_eq!(desc.category, RuleCategory::Security);
    }
}
