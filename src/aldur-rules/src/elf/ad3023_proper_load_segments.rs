//! AD3023: ProperLoadSegments
//!
//! Checks that loadable program segments follow security best practices.
//! No segment should be both writable and executable (W^X violation).

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::ElfBinary;
use aldur_parsers::elf::ph_type;

use crate::rule_ids::AD3023;

pub struct ProperLoadSegments {
    descriptor: RuleDescriptor,
}

impl ProperLoadSegments {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD3023, "ProperLoadSegments")
            .with_category(RuleCategory::Correctness)
            .with_tags(&["critical", "memory-safety", "linux-only", "android-cdd", "rhel-annocheck"])
            .with_short_description("Ensure load segments follow W^X (Write XOR Execute) principle.")
            .with_full_description(
                "Loadable program segments (PT_LOAD) should not be both writable and executable. \
                 Having segments that are W+X violates the Write XOR Execute (W^X) security \
                 principle and makes exploitation of memory corruption vulnerabilities easier. \
                 Ensure code is compiled with proper flags and not using JIT or self-modifying \
                 code patterns that require W+X memory.",
            )
            .with_fix_hint("Avoid JIT or self-modifying code; ensure W^X compliance")
            .with_default_level(FailureLevel::Error)
            .with_message(
                "Pass",
                "'{0}' has no load segments that are both writable and executable.",
            )
            .with_message(
                "Error",
                "'{0}' has {1} load segment(s) that are both writable and executable (W^X violation). \
                 Segments at addresses: {2}.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}': {2}.",
            );

        Self { descriptor }
    }

    fn find_wx_segments(elf: &ElfBinary) -> Vec<u64> {
        elf.segments
            .iter()
            .filter(|seg| {
                seg.p_type == ph_type::PT_LOAD && seg.is_writable() && seg.is_executable()
            })
            .map(|seg| seg.p_vaddr)
            .collect()
    }
}

impl Default for ProperLoadSegments {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for ProperLoadSegments {
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

        if binary.format() != BinaryFormat::ELF {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Not an ELF binary".to_string()),
            );
        }

        let elf = match binary.as_ref().as_any().downcast_ref::<ElfBinary>() {
            Some(elf) => elf,
            None => {
                return (
                    AnalysisApplicability::NotApplicableToSpecifiedTarget,
                    Some("Could not access ELF data".to_string()),
                );
            }
        };

        use aldur_parsers::elf::ElfType;

        match elf.elf_type {
            ElfType::Core | ElfType::None => {
                return (
                    AnalysisApplicability::NotApplicableToSpecifiedTarget,
                    Some("ELF is core or none".to_string()),
                );
            }
            _ => {}
        }

        (AnalysisApplicability::ApplicableToSpecifiedTarget, None)
    }

    fn analyze(&self, context: &mut AnalysisContext) {
        let file_name = context.file_name();
        let binary = context.binary().expect("Binary must be loaded").clone();

        let elf = match binary.as_ref().as_any().downcast_ref::<ElfBinary>() {
            Some(elf) => elf,
            None => {
                self.log_not_applicable(
                    context,
                    "NotApplicable_InvalidMetadata",
                    &[&file_name, self.name(), "Could not access ELF data"],
                );
                return;
            }
        };

        let wx_segments = Self::find_wx_segments(elf);

        if wx_segments.is_empty() {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            let count = wx_segments.len().to_string();
            let addresses: String = wx_segments
                .iter()
                .map(|addr| format!("0x{:x}", addr))
                .collect::<Vec<_>>()
                .join(", ");

            self.log_fail(
                context,
                FailureLevel::Error,
                "Error",
                &[&file_name, &count, &addresses],
            );
        }
    }
}
