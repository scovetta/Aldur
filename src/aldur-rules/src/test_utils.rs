//! Test utilities for Aldur
//!
//! This module provides helper functions and utilities for testing Aldur rules.

use aldur_core::{
    AnalysisApplicability, AnalysisConfig, AnalysisContext, Binary, Rule, RuleResult,
};
use aldur_parsers::ElfBinary;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Path to test fixtures directory
pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test-fixtures")
}

/// Load an ELF binary from the fixtures directory
pub fn load_fixture(name: &str) -> ElfBinary {
    let path = fixtures_dir().join(name);
    ElfBinary::load(&path).expect(&format!("Failed to load fixture: {}", name))
}

/// Create an analysis context for testing with a fixture binary
pub fn create_context(binary_name: &str) -> AnalysisContext {
    let path = fixtures_dir().join(binary_name);
    let binary = load_fixture(binary_name);
    let mut context = AnalysisContext::new(path, AnalysisConfig::default());
    context.set_binary(Arc::new(binary) as Arc<dyn Binary>);
    context
}

/// Create an analysis context from a specific path
pub fn create_context_from_path(path: impl AsRef<Path>) -> Option<AnalysisContext> {
    let path = path.as_ref();
    let binary = ElfBinary::load(path).ok()?;
    let mut context = AnalysisContext::new(path.to_path_buf(), AnalysisConfig::default());
    context.set_binary(Arc::new(binary) as Arc<dyn Binary>);
    Some(context)
}

/// Helper to run a rule and return results
pub fn run_rule(rule: &dyn Rule, binary_name: &str) -> (AnalysisApplicability, Vec<RuleResult>) {
    let mut context = create_context(binary_name);
    let (applicability, _) = rule.can_analyze(&context);
    if applicability == AnalysisApplicability::ApplicableToSpecifiedTarget {
        rule.analyze(&mut context);
    }
    (applicability, context.take_results())
}

/// Run a rule on a specific file path
pub fn run_rule_on_path(
    rule: &dyn Rule,
    path: impl AsRef<Path>,
) -> Option<(AnalysisApplicability, Vec<RuleResult>)> {
    let mut context = create_context_from_path(path)?;
    let (applicability, _) = rule.can_analyze(&context);
    if applicability == AnalysisApplicability::ApplicableToSpecifiedTarget {
        rule.analyze(&mut context);
    }
    Some((applicability, context.take_results()))
}

/// Assertion helper: check if any result is a Pass
pub fn assert_any_pass(results: &[RuleResult]) {
    assert!(
        results
            .iter()
            .any(|r| r.kind == aldur_core::ResultKind::Pass),
        "Expected at least one Pass result, got: {:?}",
        results.iter().map(|r| &r.kind).collect::<Vec<_>>()
    );
}

/// Assertion helper: check if any result is a Fail
pub fn assert_any_fail(results: &[RuleResult]) {
    assert!(
        results
            .iter()
            .any(|r| r.kind == aldur_core::ResultKind::Fail),
        "Expected at least one Fail result, got: {:?}",
        results.iter().map(|r| &r.kind).collect::<Vec<_>>()
    );
}

/// Assertion helper: check if all results are Pass
pub fn assert_all_pass(results: &[RuleResult]) {
    assert!(
        results
            .iter()
            .all(|r| r.kind == aldur_core::ResultKind::Pass),
        "Expected all results to be Pass, got: {:?}",
        results.iter().map(|r| &r.kind).collect::<Vec<_>>()
    );
}

/// Assertion helper: check if no results are Fail
pub fn assert_no_fail(results: &[RuleResult]) {
    assert!(
        !results
            .iter()
            .any(|r| r.kind == aldur_core::ResultKind::Fail),
        "Expected no Fail results, got: {:?}",
        results.iter().map(|r| &r.kind).collect::<Vec<_>>()
    );
}

/// List available fixture binaries
pub fn list_fixtures() -> Vec<String> {
    let fixtures = fixtures_dir();
    std::fs::read_dir(&fixtures)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| e.path().is_file())
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|name| !name.ends_with(".c") && !name.ends_with(".h"))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixtures_dir_exists() {
        assert!(fixtures_dir().exists());
    }

    #[test]
    fn test_load_fixture() {
        let binary = load_fixture("hardened");
        assert!(binary.is_valid());
    }

    #[test]
    fn test_list_fixtures() {
        let fixtures = list_fixtures();
        assert!(fixtures.contains(&"hardened".to_string()));
        assert!(fixtures.contains(&"no_pie".to_string()));
    }
}
