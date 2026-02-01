//! AD5060: DetectPackedBinaryMachO
//!
//! Detects Mach-O binaries that have been compressed or packed using executable packers
//! like UPX. Packed binaries strip or encrypt metadata that security analysis tools rely on,
//! making results unreliable.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::MachOBinary;

use crate::rule_ids::AD5060;

pub struct DetectPackedBinaryMachO {
    descriptor: RuleDescriptor,
}

impl DetectPackedBinaryMachO {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD5060, "DetectPackedBinary")
            .with_category(RuleCategory::Security)
            .with_tags(&["packer", "obfuscation", "reliability"])
            .with_short_description("Detect packed or obfuscated binaries.")
            .with_full_description(
                "This rule detects binaries that have been compressed or packed using executable \
                 packers like UPX. Packed binaries strip or encrypt segment information, debug \
                 information, and symbol tables that security analysis tools rely on. When a \
                 packer is detected, other analysis results should be treated as potentially \
                 unreliable.\n\n\
                 To analyze the underlying binary, you must first unpack it using the \
                 appropriate tool. See the Aldur documentation for unpacking instructions.",
            )
            .with_fix_hint("Unpack the binary before analysis. For UPX: upx -d <binary>")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Warning_Packed",
                "'{0}' appears to be packed with {1}. Analysis results may be unreliable. \
                 Unpack the binary before analysis for accurate results.",
            )
            .with_message(
                "Warning_PackedUnknown",
                "'{0}' appears to be packed or obfuscated (detected: {1}). Analysis results \
                 may be unreliable.",
            )
            .with_message("Pass", "'{0}' does not appear to be packed.");

        Self { descriptor }
    }
}

impl Default for DetectPackedBinaryMachO {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DetectPackedBinaryMachO {
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
            Some(m) => m,
            None => {
                return;
            }
        };

        let packer_info = macho.packer_info();

        if packer_info.is_packed {
            let packer_names = packer_info.packer_names();

            // Check if we detected a known packer (not just "unknown")
            let has_known_packer = packer_info
                .packers
                .iter()
                .any(|p| !matches!(p, aldur_parsers::packer::PackerType::Unknown(_)));

            if has_known_packer {
                self.log_fail(
                    context,
                    FailureLevel::Warning,
                    "Warning_Packed",
                    &[&file_name, &packer_names],
                );
            } else {
                // Unknown packer detected via heuristics
                let signatures = packer_info.signatures.join("; ");
                self.log_fail(
                    context,
                    FailureLevel::Warning,
                    "Warning_PackedUnknown",
                    &[&file_name, &signatures],
                );
            }
        } else {
            self.log_pass(context, "Pass", &[&file_name]);
        }
    }
}
