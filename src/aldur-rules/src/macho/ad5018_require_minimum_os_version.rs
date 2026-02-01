//! AD5018: RequireMinimumOSVersion
//!
//! Checks that Mach-O binaries target a sufficiently recent minimum OS version
//! to receive security updates and modern protections.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::MachOBinary;

use crate::rule_ids::AD5018;

// Minimum recommended versions (as of 2024):
// - macOS 11.0 (Big Sur) - introduced ARM support
// - iOS 14.0 - modern security features
const MIN_MACOS_MAJOR: u32 = 11;
const MIN_IOS_MAJOR: u32 = 14;

pub struct RequireMinimumOSVersion {
    descriptor: RuleDescriptor,
}

impl RequireMinimumOSVersion {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD5018, "RequireMinimumOSVersion")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "macos-only"])
            .with_short_description("Require a minimum OS version for security updates.")
            .with_full_description(
                "Targeting old OS versions means your application can run on systems that \
                 no longer receive security updates. For macOS, target at least 11.0 (Big Sur). \
                 For iOS, target at least 14.0. Older versions may lack critical security \
                 features and patches.",
            )
            .with_fix_hint("Set minimum deployment target to a recent macOS/iOS version")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' targets a sufficiently recent OS version ({1}).",
            )
            .with_message(
                "Warning",
                "'{0}' targets an old OS version ({1}). Consider updating to at least \
                 macOS 11.0 or iOS 14.0 for improved security.",
            )
            .with_message(
                "NotApplicable_NoVersionInfo",
                "'{0}' does not contain minimum OS version information.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for RequireMinimumOSVersion {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for RequireMinimumOSVersion {
    fn descriptor(&self) -> &RuleDescriptor {
        &self.descriptor
    }

    fn can_analyze(&self, context: &AnalysisContext) -> (AnalysisApplicability, Option<String>) {
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

        // Check if we have minimum OS version info
        let Some(ref min_ver) = macho.min_os_version else {
            self.log_not_applicable(context, "NotApplicable_NoVersionInfo", &[&file_name]);
            return;
        };

        let version_str = format!("{} {}", min_ver.platform, min_ver.to_version_string());

        // Check if version is sufficient based on platform
        let is_sufficient = if min_ver.platform.to_lowercase().contains("ios")
            || min_ver.platform.to_lowercase().contains("iphone")
        {
            min_ver.major >= MIN_IOS_MAJOR
        } else {
            // Assume macOS/other
            min_ver.major >= MIN_MACOS_MAJOR
        };

        if is_sufficient {
            self.log_pass(context, "Pass", &[&file_name, &version_str]);
        } else {
            self.log_fail(
                context,
                FailureLevel::Warning,
                "Warning",
                &[&file_name, &version_str],
            );
        }
    }
}
