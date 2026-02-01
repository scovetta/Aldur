//! SARIF (Static Analysis Results Interchange Format) output generation
//!
//! Implements SARIF 2.1.0 format for Aldur results.
//! See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

pub mod schema;

pub use schema::{
    ArtifactLocation, Location, Message, PhysicalLocation, Region, ReportingDescriptor,
    Result as SarifResult, Run, Sarif, Tool, ToolComponent,
};

use aldur_core::{AnalysisResult, FailureLevel, ResultKind, RuleResult};
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

/// SARIF log builder
pub struct SarifLogger {
    /// Tool name
    tool_name: String,
    /// Tool version
    tool_version: String,
    /// Rules metadata
    rules: HashMap<String, ReportingDescriptor>,
    /// Results collected
    results: Vec<SarifResult>,
    /// Whether to include hashes
    include_hashes: bool,
    /// Whether to include environment
    include_environment: bool,
}

impl SarifLogger {
    /// Create a new SARIF logger
    pub fn new(tool_name: impl Into<String>, tool_version: impl Into<String>) -> Self {
        Self {
            tool_name: tool_name.into(),
            tool_version: tool_version.into(),
            rules: HashMap::new(),
            results: Vec::new(),
            include_hashes: false,
            include_environment: false,
        }
    }

    /// Set whether to include hashes
    pub fn with_hashes(mut self, include: bool) -> Self {
        self.include_hashes = include;
        self
    }

    /// Set whether to include environment
    pub fn with_environment(mut self, include: bool) -> Self {
        self.include_environment = include;
        self
    }

    /// Add a rule descriptor
    pub fn add_rule(&mut self, rule: ReportingDescriptor) {
        self.rules.insert(rule.id.clone(), rule);
    }

    /// Add a result
    pub fn add_result(&mut self, result: SarifResult) {
        self.results.push(result);
    }

    /// Convert a RuleResult to a SARIF result
    pub fn convert_result(&mut self, rule_result: &RuleResult) {
        let level = match (&rule_result.kind, &rule_result.level) {
            (ResultKind::Fail, FailureLevel::Error) => "error",
            (ResultKind::Fail, FailureLevel::Warning) => "warning",
            (ResultKind::Fail, FailureLevel::Note) => "note",
            _ => "none",
        };

        let kind = match rule_result.kind {
            ResultKind::Pass => "pass",
            ResultKind::Fail => "fail",
            ResultKind::NotApplicable => "notApplicable",
            ResultKind::Informational => "informational",
            ResultKind::Review => "review",
            ResultKind::Open => "open",
        };

        let sarif_result = SarifResult {
            rule_id: Some(rule_result.rule_id.clone()),
            rule_index: None,
            level: Some(level.to_string()),
            kind: Some(kind.to_string()),
            message: Message {
                text: Some(rule_result.message.clone()),
                id: Some(rule_result.message_id.clone()),
                arguments: None,
            },
            locations: Some(vec![Location {
                physical_location: Some(PhysicalLocation {
                    artifact_location: Some(ArtifactLocation {
                        uri: Some(rule_result.target_path.clone()),
                        uri_base_id: None,
                        index: None,
                    }),
                    region: None,
                }),
                logical_locations: None,
            }]),
            fingerprints: None,
            partial_fingerprints: None,
            properties: if rule_result.properties.is_empty() {
                None
            } else {
                Some(rule_result.properties.clone())
            },
        };

        self.results.push(sarif_result);
    }

    /// Convert an AnalysisResult to SARIF results
    pub fn convert_analysis_result(&mut self, analysis_result: &AnalysisResult) {
        for result in &analysis_result.results {
            self.convert_result(result);
        }
    }

    /// Build the SARIF document
    pub fn build(&self) -> Sarif {
        let rules: Vec<ReportingDescriptor> = self.rules.values().cloned().collect();

        let tool = Tool {
            driver: ToolComponent {
                name: self.tool_name.clone(),
                version: Some(self.tool_version.clone()),
                information_uri: Some("https://github.com/scovetta/Aldur".to_string()),
                rules: if rules.is_empty() { None } else { Some(rules) },
                notifications: None,
            },
            extensions: None,
        };

        let run = Run {
            tool,
            invocations: None,
            artifacts: None,
            results: Some(self.results.clone()),
            taxonomies: None,
            properties: None,
        };

        Sarif {
            schema: Some(
                "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            ),
            version: "2.1.0".to_string(),
            runs: vec![run],
        }
    }

    /// Write SARIF to a file
    pub fn write_to_file(&self, path: &Path) -> std::io::Result<()> {
        let sarif = self.build();
        let json = serde_json::to_string_pretty(&sarif)?;
        let mut file = std::fs::File::create(path)?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }

    /// Write SARIF to a writer
    pub fn write<W: Write>(&self, writer: W) -> std::io::Result<()> {
        let sarif = self.build();
        serde_json::to_writer_pretty(writer, &sarif)?;
        Ok(())
    }

    /// Get results count
    pub fn result_count(&self) -> usize {
        self.results.len()
    }
}

/// Convert the failure level to SARIF level string
pub fn failure_level_to_sarif(level: FailureLevel) -> &'static str {
    match level {
        FailureLevel::None => "none",
        FailureLevel::Note => "note",
        FailureLevel::Warning => "warning",
        FailureLevel::Error => "error",
    }
}

/// Convert the result kind to SARIF kind string
pub fn result_kind_to_sarif(kind: ResultKind) -> &'static str {
    match kind {
        ResultKind::Pass => "pass",
        ResultKind::Fail => "fail",
        ResultKind::NotApplicable => "notApplicable",
        ResultKind::Informational => "informational",
        ResultKind::Review => "review",
        ResultKind::Open => "open",
    }
}
