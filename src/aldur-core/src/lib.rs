//! Core analysis engine for Aldur
//!
//! This crate provides the fundamental types and traits for binary analysis:
//! - `Binary` trait for representing parsed binaries
//! - `Rule` trait for implementing security checks
//! - `AnalysisContext` for managing analysis state
//! - Result types for reporting analysis outcomes

pub mod binary;
pub mod context;
pub mod error;
pub mod result;
pub mod rule;

pub use binary::{Binary, BinaryFormat, BinaryType};
pub use context::{AnalysisConfig, AnalysisContext};
pub use error::{AldurError, Result};
pub use result::{AnalysisResult, FailureLevel, ResultKind, RuleResult};
pub use rule::{AnalysisApplicability, Rule, RuleCategory, RuleDescriptor};
