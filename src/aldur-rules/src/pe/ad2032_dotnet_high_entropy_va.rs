//! AD2032: DotNetEnableHighEntropyVA
//!
//! Ensures .NET binaries are compiled with high-entropy virtual addresses enabled.
//! For .NET Framework, use -highentropyva. For .NET Core/5+, use <HighEntropyVA>true</HighEntropyVA>.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, Binary, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::PeBinary;

use crate::rule_ids::AD2032;

pub struct DotNetEnableHighEntropyVA {
    descriptor: RuleDescriptor,
}

impl DotNetEnableHighEntropyVA {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2032, "DotNetEnableHighEntropyVA")
            .with_category(RuleCategory::Security)
            .with_tags(&["critical", "memory-safety", "windows-only"])
            .with_short_description("Enable high-entropy virtual addresses for .NET binaries.")
            .with_full_description(
                ".NET binaries should be compiled with high-entropy virtual address space (ASLR) \
                 enabled. This significantly increases the entropy available for ASLR, making it \
                 much harder for attackers to predict memory layout. For .NET Framework, use the \
                 -highentropyva compiler flag. For .NET Core and .NET 5+, set \
                 <HighEntropyVA>true</HighEntropyVA> in your project file. This check only \
                 applies to 64-bit .NET assemblies.",
            )
            .with_fix_hint("Set <HighEntropyVA>true</HighEntropyVA> in project file")
            .with_default_level(FailureLevel::Error)
            .with_message(
                "Pass",
                "'{0}' is a .NET binary with high-entropy virtual addresses enabled.",
            )
            .with_message(
                "Error_NoHighEntropyVA",
                "'{0}' is a 64-bit .NET binary that does not have high-entropy virtual \
                 addresses enabled. For .NET Framework, compile with -highentropyva. \
                 For .NET Core/.NET 5+, add <HighEntropyVA>true</HighEntropyVA> to your \
                 project file.",
            )
            .with_message(
                "NotApplicable_NotDotNet",
                "'{0}' is not a .NET binary.",
            )
            .with_message(
                "NotApplicable_Not64Bit",
                "'{0}' is a 32-bit .NET binary. High-entropy VA is only applicable to \
                 64-bit binaries.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}': {2}.",
            );

        Self { descriptor }
    }
}

impl Default for DotNetEnableHighEntropyVA {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DotNetEnableHighEntropyVA {
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

        if binary.format() != BinaryFormat::PE {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Not a PE binary".to_string()),
            );
        }

        (AnalysisApplicability::ApplicableToSpecifiedTarget, None)
    }

    fn analyze(&self, context: &mut AnalysisContext) {
        let file_name = context.file_name();
        let binary = context.binary().expect("Binary must be loaded").clone();

        let pe = match binary.as_ref().as_any().downcast_ref::<PeBinary>() {
            Some(pe) => pe,
            None => {
                self.log_not_applicable(
                    context,
                    "NotApplicable_InvalidMetadata",
                    &[&file_name, self.name(), "Could not access PE data"],
                );
                return;
            }
        };

        // Only applicable to .NET binaries
        if !pe.is_dotnet() {
            self.log_not_applicable(context, "NotApplicable_NotDotNet", &[&file_name]);
            return;
        }

        // High-entropy VA is only meaningful for 64-bit binaries
        if !pe.is_64_bit() {
            self.log_not_applicable(context, "NotApplicable_Not64Bit", &[&file_name]);
            return;
        }

        // Check if HIGH_ENTROPY_VA and DYNAMIC_BASE are set
        if pe.is_high_entropy_va() && pe.is_dynamic_base() {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(
                context,
                FailureLevel::Error,
                "Error_NoHighEntropyVA",
                &[&file_name],
            );
        }
    }
}
