//! AD5012: ValidateSegmentPermissions
//!
//! Checks that Mach-O segments have appropriate memory protections:
//! - __TEXT should not be writable
//! - __DATA should not be executable
//! - No segment should have both write and execute permissions (W^X)

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::MachOBinary;

use crate::rule_ids::AD5012;

pub struct ValidateSegmentPermissions {
    descriptor: RuleDescriptor,
}

impl ValidateSegmentPermissions {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD5012, "ValidateSegmentPermissions")
            .with_category(RuleCategory::Security)
            .with_tags(&["critical", "memory-safety", "macos-only"])
            .with_short_description("Validate segment memory protections (W^X policy).")
            .with_full_description(
                "Segments should follow the W^X (Write XOR Execute) principle: memory should \
                 either be writable or executable, but not both. The __TEXT segment should be \
                 read-execute only (not writable), and __DATA segments should be read-write \
                 only (not executable). Violations allow attackers to inject and execute \
                 arbitrary code.",
            )
            .with_fix_hint("Ensure segments are not both writable and executable")
            .with_default_level(FailureLevel::Error)
            .with_message(
                "Pass",
                "'{0}' has correct segment permissions (no W^X violations).",
            )
            .with_message(
                "Error_WritableText",
                "'{0}' has a writable __TEXT segment. Code segments should never be writable \
                 as this allows code injection attacks.",
            )
            .with_message(
                "Error_ExecutableData",
                "'{0}' has an executable __DATA segment. Data segments should never be \
                 executable as this allows attackers to execute injected shellcode.",
            )
            .with_message(
                "Error_WXViolation",
                "'{0}' has segments with both write and execute permissions: {1}. \
                 This violates the W^X security principle.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for ValidateSegmentPermissions {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for ValidateSegmentPermissions {
    fn descriptor(&self) -> &RuleDescriptor {
        &self.descriptor
    }

    fn can_analyze(
        &self,
        context: &AnalysisContext,
    ) -> (AnalysisApplicability, Option<String>) {
        let Some(binary) = context.binary() else {
            return (
                AnalysisApplicability::NotApplicableDueToMissingTarget,
                Some("Binary not loaded".to_string()),
            );
        };

        if binary.format() != BinaryFormat::MachO {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Not a Mach-O binary".to_string()),
            );
        }

        let macho = match binary.as_ref().as_any().downcast_ref::<MachOBinary>() {
            Some(macho) => macho,
            None => {
                return (
                    AnalysisApplicability::NotApplicableToSpecifiedTarget,
                    Some("Could not access Mach-O data".to_string()),
                );
            }
        };

        use aldur_parsers::macho::MachOType;

        // Skip object files and core dumps
        match macho.file_type() {
            Some(MachOType::Object) | Some(MachOType::Core) | Some(MachOType::Dsym) => {
                return (
                    AnalysisApplicability::NotApplicableToSpecifiedTarget,
                    Some("Mach-O is object file, core dump, or dsym".to_string()),
                );
            }
            _ => {}
        }

        (AnalysisApplicability::ApplicableToSpecifiedTarget, None)
    }

    fn analyze(&self, context: &mut AnalysisContext) {
        let file_name = context.file_name();
        let binary = context.binary().expect("Binary must be loaded").clone();

        let macho = match binary.as_ref().as_any().downcast_ref::<MachOBinary>() {
            Some(macho) => macho,
            None => {
                self.log_not_applicable(
                    context,
                    "NotApplicable_InvalidMetadata",
                    &[&file_name, self.name(), "Could not access Mach-O data"],
                );
                return;
            }
        };

        // Check for writable __TEXT
        if macho.has_writable_text_segment() {
            self.log_fail(context, FailureLevel::Error, "Error_WritableText", &[&file_name]);
            return;
        }

        // Check for executable __DATA
        if macho.has_executable_data_segment() {
            self.log_fail(context, FailureLevel::Error, "Error_ExecutableData", &[&file_name]);
            return;
        }

        // Check for any W^X violations
        let violating_segments = macho.get_wxorx_violating_segments();
        if !violating_segments.is_empty() {
            let segment_names: Vec<&str> = violating_segments.iter().map(|s| s.name.as_str()).collect();
            let names_str = segment_names.join(", ");
            self.log_fail(context, FailureLevel::Error, "Error_WXViolation", &[&file_name, &names_str]);
            return;
        }

        self.log_pass(context, "Pass", &[&file_name]);
    }
}
