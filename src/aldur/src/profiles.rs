//! Security profiles for different environments (tag-based)
//!
//! Profiles are defined as queries over rule tags, making them:
//! - Self-maintaining: new rules with matching tags are automatically included
//! - Declarative: profiles describe *what* they want, not specific rule IDs
//! - Flexible: easy to create custom profiles
//!
//! ## Standard Tags
//!
//! ### Severity Tags
//! - `critical`: Must-have security features (PIE, NX, stack protection)
//! - `recommended`: Strongly recommended but not always required
//! - `hardening`: Extra hardening for high-security environments
//! - `debug-only`: Only applicable for debug/test builds (sanitizers)
//! - `optimization`: Performance and binary size optimizations
//!
//! ### Feature Tags
//! - `memory-safety`: Memory corruption mitigations (ASLR, stack canary, FORTIFY)
//! - `control-flow`: Control-flow integrity (CFG, CET, BTI, CFI)
//! - `code-integrity`: Code signing and integrity checks
//! - `crypto`: Cryptography-related checks
//!
//! ### Platform Tags
//! - `intel-only`: Intel-specific features (CET, Shadow Stack)
//! - `arm-only`: ARM-specific features (BTI, PAC, MTE)
//! - `windows-only`: Windows-specific checks
//! - `linux-only`: Linux-specific checks
//! - `macos-only`: macOS-specific checks
//!
//! ### Compliance Tags
//! - `android-cdd`: Android Compatibility Definition requirements
//! - `rhel-annocheck`: RHEL/Fedora annocheck requirements
//! - `fips`: FIPS 140-2/3 relevant checks
//! - `openssf`: OpenSSF Compiler Hardening Guide for C and C++

use aldur_core::{FailureLevel, Rule, RuleDescriptor};
use serde::{Deserialize, Serialize};

/// A tag-based security profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityProfile {
    /// Profile name
    pub name: String,
    /// Profile description
    pub description: String,
    /// Tags that rules MUST have (all of these)
    #[serde(default)]
    pub require_all: Vec<String>,
    /// Tags where rules must have at least one
    #[serde(default)]
    pub require_any: Vec<String>,
    /// Tags that exclude rules (none of these)
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Elevate rules with these tags to Error level
    #[serde(default)]
    pub elevate_to_error: Vec<String>,
    /// Elevate rules with these tags to Warning level
    #[serde(default)]
    pub elevate_to_warning: Vec<String>,
}

impl SecurityProfile {
    /// Create a new empty profile (includes all rules by default)
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            require_all: Vec::new(),
            require_any: Vec::new(),
            exclude: Vec::new(),
            elevate_to_error: Vec::new(),
            elevate_to_warning: Vec::new(),
        }
    }

    /// Require all rules to have ALL of these tags
    #[allow(dead_code)]
    pub fn require_all_tagged(mut self, tags: &[&str]) -> Self {
        self.require_all.extend(tags.iter().map(|s| s.to_string()));
        self
    }

    /// Require rules to have at least one of these tags
    pub fn require_any_tagged(mut self, tags: &[&str]) -> Self {
        self.require_any.extend(tags.iter().map(|s| s.to_string()));
        self
    }

    /// Exclude rules that have any of these tags
    pub fn exclude_tagged(mut self, tags: &[&str]) -> Self {
        self.exclude.extend(tags.iter().map(|s| s.to_string()));
        self
    }

    /// Elevate matching rules to Error level
    pub fn elevate_to_error_tagged(mut self, tags: &[&str]) -> Self {
        self.elevate_to_error.extend(tags.iter().map(|s| s.to_string()));
        self
    }

    /// Elevate matching rules to Warning level
    #[allow(dead_code)]
    pub fn elevate_to_warning_tagged(mut self, tags: &[&str]) -> Self {
        self.elevate_to_warning.extend(tags.iter().map(|s| s.to_string()));
        self
    }

    /// Check if a rule matches this profile's tag requirements
    pub fn matches_rule(&self, descriptor: &RuleDescriptor) -> bool {
        // Check require_all: rule must have ALL these tags
        if !self.require_all.is_empty() {
            let has_all = self.require_all.iter().all(|tag| descriptor.has_tag(tag));
            if !has_all {
                return false;
            }
        }

        // Check require_any: rule must have at least ONE of these tags
        if !self.require_any.is_empty() {
            let has_any = self.require_any.iter().any(|tag| descriptor.has_tag(tag));
            if !has_any {
                return false;
            }
        }

        // Check exclude: rule must NOT have ANY of these tags
        if !self.exclude.is_empty() {
            let has_excluded = self.exclude.iter().any(|tag| descriptor.has_tag(tag));
            if has_excluded {
                return false;
            }
        }

        true
    }

    /// Get the level override for a rule based on its tags
    pub fn get_rule_level(&self, descriptor: &RuleDescriptor) -> Option<FailureLevel> {
        // Check error elevation first (highest priority)
        if !self.elevate_to_error.is_empty() {
            let should_elevate = self.elevate_to_error.iter().any(|tag| descriptor.has_tag(tag));
            if should_elevate {
                return Some(FailureLevel::Error);
            }
        }

        // Check warning elevation
        if !self.elevate_to_warning.is_empty() {
            let should_elevate = self.elevate_to_warning.iter().any(|tag| descriptor.has_tag(tag));
            if should_elevate {
                return Some(FailureLevel::Warning);
            }
        }

        None
    }

    /// Filter a list of rules to only those matching this profile
    #[allow(dead_code)]
    pub fn filter_rules<'a>(&self, rules: &'a [Box<dyn Rule>]) -> Vec<&'a dyn Rule> {
        rules
            .iter()
            .filter(|r| self.matches_rule(r.descriptor()))
            .map(|r| r.as_ref())
            .collect()
    }
}

// ============================================================================
// Standard Profiles
// ============================================================================

/// Default profile: all rules at their default levels, excluding nightly-only rules
/// Also excludes hardening (use strict), debug-only (for test builds), and optimization (use optimization profile)
pub fn default_profile() -> SecurityProfile {
    SecurityProfile::new(
        "default",
        "Standard security checks at recommended levels",
    )
    .exclude_tagged(&["nightly", "hardening", "debug-only", "optimization"])
}

/// Strict profile: all security rules elevated to error, include hardening
pub fn strict_profile() -> SecurityProfile {
    SecurityProfile::new(
        "strict",
        "Maximum security: all checks at error level",
    )
    .elevate_to_error_tagged(&["critical", "recommended", "hardening", "memory-safety", "control-flow"])
}

/// Relaxed profile: only critical security checks
pub fn relaxed_profile() -> SecurityProfile {
    SecurityProfile::new(
        "relaxed",
        "Only critical security checks (for legacy/compatibility)",
    )
    .require_any_tagged(&["critical"])
    .exclude_tagged(&["debug-only", "hardening"])
}

/// Android profile: Android CDD requirements
pub fn android_profile() -> SecurityProfile {
    SecurityProfile::new(
        "android",
        "Android security requirements (based on Android CDD)",
    )
    .require_any_tagged(&["critical", "android-cdd", "memory-safety"])
    .exclude_tagged(&["intel-only", "windows-only", "macos-only"])
    .elevate_to_error_tagged(&["critical", "android-cdd"])
}

/// RHEL profile: Red Hat Enterprise Linux hardening (annocheck-compatible)
pub fn rhel_profile() -> SecurityProfile {
    SecurityProfile::new(
        "rhel",
        "Red Hat Enterprise Linux hardening requirements",
    )
    .require_any_tagged(&["critical", "rhel-annocheck", "memory-safety", "control-flow"])
    .exclude_tagged(&["arm-only", "windows-only", "macos-only", "debug-only"])
    .elevate_to_error_tagged(&["critical", "rhel-annocheck"])
}

/// FIPS profile: FIPS 140-2/3 compliance focus
pub fn fips_profile() -> SecurityProfile {
    SecurityProfile::new(
        "fips",
        "FIPS 140-2/3 compliance-focused checks",
    )
    .require_any_tagged(&["critical", "fips", "crypto", "memory-safety"])
    .exclude_tagged(&["debug-only"])
    .elevate_to_error_tagged(&["critical", "fips", "crypto"])
}

/// OpenSSF profile: OpenSSF Compiler Hardening Guide compliance
///
/// This profile enforces the recommendations from the OpenSSF
/// "Compiler Options Hardening Guide for C and C++" which covers:
/// - PIE (Position Independent Executable)
/// - Non-executable stack
/// - Stack protector (canary)
/// - Stack clash protection
/// - RELRO + BIND_NOW
/// - Control-flow protection (CET on x86_64, BTI/PAC on AArch64)
/// - FORTIFY_SOURCE
/// - Exception handling frames
/// - Restrict dlopen (for shared libraries)
///
/// See: https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html
pub fn openssf_profile() -> SecurityProfile {
    SecurityProfile::new(
        "openssf",
        "OpenSSF Compiler Hardening Guide compliance",
    )
    .require_any_tagged(&["openssf"])
    .exclude_tagged(&["debug-only"])
    .elevate_to_error_tagged(&["critical", "openssf"])
}

/// Nightly profile: includes rules that require Rust nightly compiler features
pub fn nightly_profile() -> SecurityProfile {
    SecurityProfile::new(
        "nightly",
        "All checks including those requiring Rust nightly compiler",
    )
    // Include all rules, no exclusions for nightly
}

/// Optimization profile: performance and binary size optimization checks
pub fn optimization_profile() -> SecurityProfile {
    SecurityProfile::new(
        "optimization",
        "Performance and binary size optimization checks",
    )
    .require_any_tagged(&["optimization"])
}

/// Available profile names
pub const PROFILE_NAMES: &[&str] = &["default", "strict", "relaxed", "android", "rhel", "fips", "openssf", "nightly", "optimization"];

/// Get a profile by name
pub fn get_profile(name: &str) -> Option<SecurityProfile> {
    match name.to_lowercase().as_str() {
        "default" => Some(default_profile()),
        "strict" => Some(strict_profile()),
        "relaxed" => Some(relaxed_profile()),
        "android" => Some(android_profile()),
        "rhel" => Some(rhel_profile()),
        "fips" => Some(fips_profile()),
        "openssf" => Some(openssf_profile()),
        "nightly" => Some(nightly_profile()),
        "optimization" => Some(optimization_profile()),
        _ => None,
    }
}

/// List all available profiles with descriptions
pub fn list_profiles() -> Vec<(&'static str, &'static str)> {
    vec![
        ("default", "Standard security checks at recommended levels"),
        ("strict", "Maximum security: all checks at error level"),
        ("relaxed", "Only critical security checks (for legacy/compatibility)"),
        ("android", "Android security requirements (based on Android CDD)"),
        ("rhel", "Red Hat Enterprise Linux hardening requirements"),
        ("fips", "FIPS 140-2/3 compliance-focused checks"),
        ("openssf", "OpenSSF Compiler Hardening Guide compliance"),
        ("nightly", "All checks including those requiring Rust nightly compiler"),
        ("optimization", "Performance and binary size optimization checks"),
    ]
}

/// Standard tags documentation
#[allow(dead_code)]
pub fn standard_tags() -> Vec<(&'static str, &'static str)> {
    vec![
        // Severity
        ("critical", "Must-have security features (PIE, NX, stack protection)"),
        ("recommended", "Strongly recommended security features"),
        ("hardening", "Extra hardening for high-security environments"),
        ("debug-only", "Only for debug/test builds (sanitizers)"),
        ("nightly", "Requires Rust nightly compiler (unstable features)"),
        ("optimization", "Performance and binary size optimizations"),
        // Features
        ("memory-safety", "Memory corruption mitigations"),
        ("control-flow", "Control-flow integrity features"),
        ("code-integrity", "Code signing and integrity"),
        ("crypto", "Cryptography-related checks"),
        // Platforms
        ("intel-only", "Intel-specific (CET, Shadow Stack)"),
        ("arm-only", "ARM-specific (BTI, PAC, MTE)"),
        ("windows-only", "Windows-specific"),
        ("linux-only", "Linux-specific"),
        ("macos-only", "macOS-specific"),
        // Compliance
        ("android-cdd", "Android CDD requirement"),
        ("rhel-annocheck", "RHEL annocheck requirement"),
        ("fips", "FIPS 140 relevant"),
        ("openssf", "OpenSSF Compiler Hardening Guide"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_descriptor_with_tags(id: &str, tags: &[&str]) -> RuleDescriptor {
        RuleDescriptor::new(id, "TestRule").with_tags(tags)
    }

    #[test]
    fn test_default_profile_includes_all() {
        let profile = default_profile();
        let desc = make_descriptor_with_tags("AD0001", &["critical"]);
        assert!(profile.matches_rule(&desc));

        let desc2 = make_descriptor_with_tags("AD0002", &[]);
        assert!(profile.matches_rule(&desc2));
    }

    #[test]
    fn test_relaxed_profile_requires_critical() {
        let profile = relaxed_profile();

        let critical = make_descriptor_with_tags("AD0001", &["critical"]);
        assert!(profile.matches_rule(&critical));

        let recommended = make_descriptor_with_tags("AD0002", &["recommended"]);
        assert!(!profile.matches_rule(&recommended));
    }

    #[test]
    fn test_android_excludes_intel() {
        let profile = android_profile();

        let intel_rule = make_descriptor_with_tags("AD0001", &["critical", "intel-only"]);
        assert!(!profile.matches_rule(&intel_rule));

        let arm_rule = make_descriptor_with_tags("AD0002", &["critical", "arm-only"]);
        assert!(profile.matches_rule(&arm_rule));
    }

    #[test]
    fn test_strict_elevates_to_error() {
        let profile = strict_profile();
        let desc = make_descriptor_with_tags("AD0001", &["critical"]);

        assert_eq!(profile.get_rule_level(&desc), Some(FailureLevel::Error));
    }

    #[test]
    fn test_profile_names() {
        for name in PROFILE_NAMES {
            assert!(get_profile(name).is_some(), "Profile {} should exist", name);
        }
    }
}
