//! SARIF schema types
//!
//! Rust types representing the SARIF 2.1.0 JSON schema.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Root SARIF log object
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Sarif {
    /// URI of the JSON schema
    #[serde(rename = "$schema", skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    /// SARIF specification version
    pub version: String,
    /// Analysis runs
    pub runs: Vec<Run>,
}

/// A single run of a static analysis tool
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Run {
    /// The analysis tool that was run
    pub tool: Tool,
    /// Information about the invocation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invocations: Option<Vec<Invocation>>,
    /// Artifacts that were analyzed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<Vec<Artifact>>,
    /// Results of the analysis
    #[serde(skip_serializing_if = "Option::is_none")]
    pub results: Option<Vec<Result>>,
    /// Taxonomies referenced by results
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taxonomies: Option<Vec<ToolComponent>>,
    /// Custom properties
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<HashMap<String, serde_json::Value>>,
}

/// Description of the analysis tool
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tool {
    /// The primary tool component
    pub driver: ToolComponent,
    /// Extension tool components (plugins)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Vec<ToolComponent>>,
}

/// A component of a tool (driver or extension)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolComponent {
    /// Tool name
    pub name: String,
    /// Tool version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// URI with more information about the tool
    #[serde(skip_serializing_if = "Option::is_none")]
    pub information_uri: Option<String>,
    /// Rules defined by this component
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<ReportingDescriptor>>,
    /// Notifications defined by this component
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notifications: Option<Vec<ReportingDescriptor>>,
}

/// A rule (reporting descriptor)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportingDescriptor {
    /// Rule identifier
    pub id: String,
    /// Rule name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Short description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_description: Option<MultiformatMessageString>,
    /// Full description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_description: Option<MultiformatMessageString>,
    /// Help URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help_uri: Option<String>,
    /// Help text
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<MultiformatMessageString>,
    /// Default severity level
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_configuration: Option<ReportingConfiguration>,
    /// Message strings
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_strings: Option<HashMap<String, MultiformatMessageString>>,
    /// Custom properties
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<HashMap<String, serde_json::Value>>,
}

/// Reporting configuration for a rule
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportingConfiguration {
    /// Whether the rule is enabled
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Default severity level
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    /// Rule parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<HashMap<String, serde_json::Value>>,
}

/// A message in multiple formats
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MultiformatMessageString {
    /// Plain text message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Markdown message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub markdown: Option<String>,
}

impl MultiformatMessageString {
    /// Create from plain text
    pub fn text(s: impl Into<String>) -> Self {
        Self {
            text: Some(s.into()),
            markdown: None,
        }
    }
}

/// Information about a tool invocation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Invocation {
    /// Command line
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    /// Arguments
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Vec<String>>,
    /// Working directory
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<ArtifactLocation>,
    /// Start time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time_utc: Option<String>,
    /// End time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time_utc: Option<String>,
    /// Exit code
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Whether execution was successful
    pub execution_successful: bool,
    /// Environment variables
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment_variables: Option<HashMap<String, String>>,
}

/// An analyzed artifact (file)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Artifact {
    /// Location of the artifact
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<ArtifactLocation>,
    /// MIME type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Hashes of the artifact
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashes: Option<HashMap<String, String>>,
    /// Size in bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<i64>,
}

/// Location of an artifact
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactLocation {
    /// URI to the artifact
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    /// Base URI identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri_base_id: Option<String>,
    /// Index in artifacts array
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<i32>,
}

/// A single analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Result {
    /// Rule identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// Rule index in rules array
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_index: Option<i32>,
    /// Severity level
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    /// Result kind
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Message
    pub message: Message,
    /// Locations where the result was found
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locations: Option<Vec<Location>>,
    /// Fingerprints for result matching
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprints: Option<HashMap<String, String>>,
    /// Partial fingerprints
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial_fingerprints: Option<HashMap<String, String>>,
    /// Custom properties
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<HashMap<String, String>>,
}

/// A message
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    /// Plain text message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Message ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Arguments for message formatting
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Vec<String>>,
}

/// A location
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Location {
    /// Physical location
    #[serde(skip_serializing_if = "Option::is_none")]
    pub physical_location: Option<PhysicalLocation>,
    /// Logical locations
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logical_locations: Option<Vec<LogicalLocation>>,
}

/// A physical location (file and position)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PhysicalLocation {
    /// Artifact location
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_location: Option<ArtifactLocation>,
    /// Region within the artifact
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<Region>,
}

/// A region within a file
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Region {
    /// Start line (1-based)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_line: Option<i32>,
    /// Start column (1-based)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_column: Option<i32>,
    /// End line (1-based)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<i32>,
    /// End column (1-based)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_column: Option<i32>,
    /// Byte offset
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_offset: Option<i64>,
    /// Byte length
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_length: Option<i64>,
}

/// A logical location (function, class, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogicalLocation {
    /// Name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Fully qualified name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fully_qualified_name: Option<String>,
    /// Kind (function, class, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}
