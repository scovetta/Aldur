//! Custom user-defined profiles
//!
//! Supports loading profiles from a configuration file with the format:
//!
//! ```text
//! [profile_name]
//! profile:default        # Optional: inherit from a built-in profile
//! +AD3033                # Include specific rule (overrides profile exclusion)
//! -AD3041                # Exclude specific rule
//! +AD3035
//!
//! [another_profile]
//! profile:strict
//! -AD2011
//! -AD2012
//! ```
//!
//! If no `profile:` line is specified, the profile starts with no rules
//! and only the explicitly included rules (+ADXXXX) will be active.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use crate::profiles::{SecurityProfile, get_profile};
use aldur_core::RuleDescriptor;

/// A custom profile definition loaded from a file
#[derive(Debug, Clone)]
pub struct CustomProfile {
    /// Profile name
    pub name: String,
    /// Base profile to inherit from (None means empty/no rules by default)
    pub base_profile: Option<String>,
    /// Rule IDs to explicitly include (overrides base profile exclusions)
    pub include_rules: HashSet<String>,
    /// Rule IDs to explicitly exclude
    pub exclude_rules: HashSet<String>,
}

impl CustomProfile {
    /// Create a new empty custom profile
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            base_profile: None,
            include_rules: HashSet::new(),
            exclude_rules: HashSet::new(),
        }
    }

    /// Check if a rule matches this custom profile
    pub fn matches_rule(&self, descriptor: &RuleDescriptor) -> bool {
        let rule_id = descriptor.id.to_uppercase();

        // If rule is explicitly excluded, skip it
        if self.exclude_rules.contains(&rule_id) {
            return false;
        }

        // If rule is explicitly included, include it regardless of base profile
        if self.include_rules.contains(&rule_id) {
            return true;
        }

        // If we have a base profile, delegate to it
        if let Some(ref base_name) = self.base_profile {
            if let Some(base) = get_profile(base_name) {
                return base.matches_rule(descriptor);
            }
        }

        // No base profile and not explicitly included = not matched
        // (empty profile with no base means only explicitly included rules)
        self.base_profile.is_some()
    }

    /// Get the base SecurityProfile if one is set
    pub fn get_base_profile(&self) -> Option<SecurityProfile> {
        self.base_profile
            .as_ref()
            .and_then(|name| get_profile(name))
    }
}

/// A collection of custom profiles loaded from a file
#[derive(Debug, Clone, Default)]
pub struct CustomProfileRegistry {
    profiles: HashMap<String, CustomProfile>,
}

impl CustomProfileRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            profiles: HashMap::new(),
        }
    }

    /// Load profiles from a file
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read custom profiles from {}", path.display()))?;

        Self::parse(&content)
            .with_context(|| format!("Failed to parse custom profiles from {}", path.display()))
    }

    /// Parse profile definitions from a string
    pub fn parse(content: &str) -> Result<Self> {
        let mut registry = Self::new();
        let mut current_profile: Option<CustomProfile> = None;

        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }

            // Check for profile header [profile_name]
            if line.starts_with('[') && line.ends_with(']') {
                // Save previous profile if any
                if let Some(profile) = current_profile.take() {
                    registry.add_profile(profile);
                }

                // Start new profile
                let name = &line[1..line.len() - 1];
                if name.is_empty() {
                    anyhow::bail!("Empty profile name at line {}", line_num + 1);
                }
                current_profile = Some(CustomProfile::new(name));
                continue;
            }

            // Must have a current profile for other lines
            let profile = current_profile.as_mut().ok_or_else(|| {
                anyhow::anyhow!(
                    "Line {} is outside of a profile section: '{}'",
                    line_num + 1,
                    line
                )
            })?;

            // Parse the line
            if let Some(base) = line.strip_prefix("profile:") {
                let base = base.trim();
                if get_profile(base).is_none() {
                    anyhow::bail!(
                        "Unknown base profile '{}' at line {}. Available: default, strict, relaxed, android, rhel, fips, openssf, nightly",
                        base,
                        line_num + 1
                    );
                }
                profile.base_profile = Some(base.to_string());
            } else if let Some(rule_id) = line.strip_prefix('+') {
                let rule_id = rule_id.trim().to_uppercase();
                if !rule_id.starts_with("AD") {
                    anyhow::bail!(
                        "Invalid rule ID '{}' at line {} (should start with AD)",
                        rule_id,
                        line_num + 1
                    );
                }
                profile.include_rules.insert(rule_id);
            } else if let Some(rule_id) = line.strip_prefix('-') {
                let rule_id = rule_id.trim().to_uppercase();
                if !rule_id.starts_with("AD") {
                    anyhow::bail!(
                        "Invalid rule ID '{}' at line {} (should start with AD)",
                        rule_id,
                        line_num + 1
                    );
                }
                profile.exclude_rules.insert(rule_id);
            } else {
                anyhow::bail!(
                    "Unrecognized line at line {}: '{}'. Expected profile:name, +ADXXXX, or -ADXXXX",
                    line_num + 1,
                    line
                );
            }
        }

        // Don't forget the last profile
        if let Some(profile) = current_profile {
            registry.add_profile(profile);
        }

        Ok(registry)
    }

    /// Add a profile to the registry
    pub fn add_profile(&mut self, profile: CustomProfile) {
        self.profiles.insert(profile.name.to_lowercase(), profile);
    }

    /// Get a custom profile by name
    pub fn get(&self, name: &str) -> Option<&CustomProfile> {
        self.profiles.get(&name.to_lowercase())
    }

    /// Get all profile names
    pub fn names(&self) -> Vec<&str> {
        self.profiles.keys().map(|s| s.as_str()).collect()
    }

    /// Check if registry is empty
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_profile() {
        let content = r#"
[my_profile]
profile:default
+AD3033
-AD3041
"#;
        let registry = CustomProfileRegistry::parse(content).unwrap();
        let profile = registry.get("my_profile").unwrap();

        assert_eq!(profile.name, "my_profile");
        assert_eq!(profile.base_profile, Some("default".to_string()));
        assert!(profile.include_rules.contains("AD3033"));
        assert!(profile.exclude_rules.contains("AD3041"));
    }

    #[test]
    fn test_parse_multiple_profiles() {
        let content = r#"
[first]
profile:strict
-AD2011

[second]
profile:relaxed
+AD3033
+AD3035
"#;
        let registry = CustomProfileRegistry::parse(content).unwrap();

        let first = registry.get("first").unwrap();
        assert_eq!(first.base_profile, Some("strict".to_string()));
        assert!(first.exclude_rules.contains("AD2011"));

        let second = registry.get("second").unwrap();
        assert_eq!(second.base_profile, Some("relaxed".to_string()));
        assert!(second.include_rules.contains("AD3033"));
        assert!(second.include_rules.contains("AD3035"));
    }

    #[test]
    fn test_parse_empty_base_profile() {
        let content = r#"
[minimal]
+AD3001
+AD3003
+AD3010
"#;
        let registry = CustomProfileRegistry::parse(content).unwrap();
        let profile = registry.get("minimal").unwrap();

        assert!(profile.base_profile.is_none());
        assert_eq!(profile.include_rules.len(), 3);
    }

    #[test]
    fn test_parse_with_comments() {
        let content = r#"
# This is a comment
[my_profile]
profile:default
# Include nightly rule
+AD3033
; This is also a comment
-AD3041
"#;
        let registry = CustomProfileRegistry::parse(content).unwrap();
        let profile = registry.get("my_profile").unwrap();

        assert!(profile.include_rules.contains("AD3033"));
        assert!(profile.exclude_rules.contains("AD3041"));
    }

    #[test]
    fn test_parse_case_insensitive_rules() {
        let content = r#"
[test]
profile:default
+ad3033
-Ad3041
"#;
        let registry = CustomProfileRegistry::parse(content).unwrap();
        let profile = registry.get("test").unwrap();

        assert!(profile.include_rules.contains("AD3033"));
        assert!(profile.exclude_rules.contains("AD3041"));
    }

    #[test]
    fn test_parse_invalid_base_profile() {
        let content = r#"
[test]
profile:nonexistent
"#;
        let result = CustomProfileRegistry::parse(content);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Unknown base profile")
        );
    }

    #[test]
    fn test_matches_rule_with_base() {
        // Create a mock descriptor
        fn make_descriptor(id: &str, tags: &[&str]) -> RuleDescriptor {
            RuleDescriptor::new(id, "Test").with_tags(tags)
        }

        let content = r#"
[test]
profile:default
+AD3033
-AD3041
"#;
        let registry = CustomProfileRegistry::parse(content).unwrap();
        let profile = registry.get("test").unwrap();

        // AD3033 is explicitly included (would be excluded by default profile's nightly exclusion)
        let nightly_rule = make_descriptor("AD3033", &["nightly"]);
        assert!(profile.matches_rule(&nightly_rule));

        // AD3041 is explicitly excluded
        let excluded_rule = make_descriptor("AD3041", &["critical"]);
        assert!(!profile.matches_rule(&excluded_rule));

        // Regular rule should be included via base profile
        let regular_rule = make_descriptor("AD3001", &["critical"]);
        assert!(profile.matches_rule(&regular_rule));
    }

    #[test]
    fn test_matches_rule_no_base() {
        fn make_descriptor(id: &str, tags: &[&str]) -> RuleDescriptor {
            RuleDescriptor::new(id, "Test").with_tags(tags)
        }

        let content = r#"
[minimal]
+AD3001
+AD3003
"#;
        let registry = CustomProfileRegistry::parse(content).unwrap();
        let profile = registry.get("minimal").unwrap();

        // Only explicitly included rules match
        assert!(profile.matches_rule(&make_descriptor("AD3001", &["critical"])));
        assert!(profile.matches_rule(&make_descriptor("AD3003", &["critical"])));

        // Others don't match
        assert!(!profile.matches_rule(&make_descriptor("AD3010", &["critical"])));
    }
}
