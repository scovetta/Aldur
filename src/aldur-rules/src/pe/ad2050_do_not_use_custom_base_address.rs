//! AD2050: DoNotUseCustomBaseAddress
//!
//! PE binaries should not use a custom base address specified via /BASE.
//! Using a fixed base address defeats Address Space Layout Randomization (ASLR).

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, BinaryType, FailureLevel, Rule,
    RuleCategory, RuleDescriptor,
};
use aldur_parsers::PeBinary;

use crate::rule_ids::AD2050;

/// Default image base for 32-bit executables
const DEFAULT_IMAGE_BASE_32: u64 = 0x00400000;
/// Default image base for 64-bit executables
const DEFAULT_IMAGE_BASE_64: u64 = 0x0000000140000000;
/// Default image base for 32-bit DLLs
const DEFAULT_IMAGE_BASE_DLL_32: u64 = 0x10000000;
/// Default image base for 64-bit DLLs
const DEFAULT_IMAGE_BASE_DLL_64: u64 = 0x0000000180000000;

pub struct DoNotUseCustomBaseAddress {
    descriptor: RuleDescriptor,
}

impl DoNotUseCustomBaseAddress {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2050, "DoNotUseCustomBaseAddress")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "memory-safety", "windows-only"])
            .with_short_description("Do not use a custom base address for binaries.")
            .with_full_description(
                "PE binaries should not be built with a custom base address specified via the \
                 /BASE linker option. Using a fixed base address defeats Address Space Layout \
                 Randomization (ASLR), an important security mitigation that makes it more \
                 difficult for attackers to exploit memory corruption vulnerabilities. Modern \
                 binaries should use the default base address and be linked with /DYNAMICBASE \
                 to enable ASLR.",
            )
            .with_fix_hint("Remove /BASE linker option and use /DYNAMICBASE")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' uses a standard base address (0x{1:X}), which is compatible with ASLR.",
            )
            .with_message(
                "Warning_CustomBaseAddress",
                "'{0}' uses a custom base address (0x{1:X}) instead of the default. This may \
                 indicate the binary was built with /BASE, which can reduce the effectiveness \
                 of Address Space Layout Randomization (ASLR). Remove the /BASE linker option \
                 to use the default base address.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }

    /// Check if the image base is a standard default value
    fn is_default_base_address(image_base: u64, is_64_bit: bool, is_dll: bool) -> bool {
        match (is_64_bit, is_dll) {
            (true, true) => image_base == DEFAULT_IMAGE_BASE_DLL_64,
            (true, false) => image_base == DEFAULT_IMAGE_BASE_64,
            (false, true) => image_base == DEFAULT_IMAGE_BASE_DLL_32,
            (false, false) => image_base == DEFAULT_IMAGE_BASE_32,
        }
    }
}

impl Default for DoNotUseCustomBaseAddress {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DoNotUseCustomBaseAddress {
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

        let image_base = pe.image_base;
        let is_64_bit = binary.is_64_bit();
        let is_dll = binary.binary_type() == BinaryType::DynamicLibrary;

        if Self::is_default_base_address(image_base, is_64_bit, is_dll) {
            self.log_pass(context, "Pass", &[&file_name, &format!("{:X}", image_base)]);
        } else {
            self.log_fail(
                context,
                FailureLevel::Warning,
                "Warning_CustomBaseAddress",
                &[&file_name, &format!("{:X}", image_base)],
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_descriptor() {
        let rule = DoNotUseCustomBaseAddress::new();
        assert_eq!(rule.descriptor().id, AD2050);
        assert_eq!(rule.descriptor().name, "DoNotUseCustomBaseAddress");
    }

    #[test]
    fn test_default_base_addresses() {
        // 64-bit executable
        assert!(DoNotUseCustomBaseAddress::is_default_base_address(
            0x0000000140000000,
            true,
            false
        ));
        // 64-bit DLL
        assert!(DoNotUseCustomBaseAddress::is_default_base_address(
            0x0000000180000000,
            true,
            true
        ));
        // 32-bit executable
        assert!(DoNotUseCustomBaseAddress::is_default_base_address(
            0x00400000, false, false
        ));
        // 32-bit DLL
        assert!(DoNotUseCustomBaseAddress::is_default_base_address(
            0x10000000, false, true
        ));
        // Custom base address
        assert!(!DoNotUseCustomBaseAddress::is_default_base_address(
            0x12345678, false, false
        ));
    }
}
