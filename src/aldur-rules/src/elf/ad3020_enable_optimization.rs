//! AD3020: EnableOptimization
//!
//! Checks that binaries are compiled with at least -O2 optimization.
//! Unoptimized binaries may have security issues and performance problems.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{DwarfInfo, ElfBinary};

use crate::rule_ids::AD3020;

pub struct EnableOptimization {
    descriptor: RuleDescriptor,
}

impl EnableOptimization {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD3020, "EnableOptimization")
            .with_category(RuleCategory::Performance)
            .with_tags(&["recommended", "linux-only"])
            .with_short_description("Enable compiler optimization (-O2 or higher).")
            .with_full_description(
                "Production binaries should be compiled with optimization level -O2 or higher. \
                 Unoptimized (-O0) or minimally optimized (-O1) code may have security issues \
                 that optimization eliminates, such as stack usage patterns that increase \
                 vulnerability to buffer overflows. Optimization also enables security features \
                 like FORTIFY_SOURCE to work correctly.",
            )
            .with_fix_hint("Compile with -O2 or -O3")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' was compiled with optimization level {1}.",
            )
            .with_message(
                "Warning_LowOptimization",
                "'{0}' was compiled with low optimization level {1}. Production builds \
                 should use -O2 or higher for security and performance.",
            )
            .with_message(
                "Warning_NoOptimization",
                "'{0}' appears to be compiled without optimization. Production builds \
                 should use -O2 or higher.",
            )
            .with_message(
                "NotApplicable_NoDebugInfo",
                "'{0}' does not contain debug information to determine optimization level.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}': {2}.",
            );

        Self { descriptor }
    }

    fn check_optimization(elf: &ElfBinary) -> Option<(i32, String)> {
        if let Ok(dwarf_info) = DwarfInfo::parse(elf.data()) {
            if dwarf_info.has_debug_info && !dwarf_info.compilation_units.is_empty() {
                // Get the first optimization level we find
                for cu in &dwarf_info.compilation_units {
                    if let Some(ref opt) = cu.parsed_info.optimization_level {
                        let level = match opt.as_str() {
                            "-O0" => 0,
                            "-O1" | "-O" => 1,
                            "-O2" => 2,
                            "-O3" => 3,
                            "-Os" => 2,
                            "-Oz" => 2,
                            "-Ofast" => 3,
                            "-Og" => 1,
                            _ => continue,
                        };
                        return Some((level, opt.clone()));
                    }
                }
                // If we have debug info but no optimization flag, assume -O0
                return Some((0, "-O0".to_string()));
            }
        }
        None
    }
}

impl Default for EnableOptimization {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableOptimization {
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

        if binary.format() != BinaryFormat::ELF {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Not an ELF binary".to_string()),
            );
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

        match Self::check_optimization(elf) {
            Some((level, opt_str)) => {
                if level >= 2 {
                    self.log_pass(context, "Pass", &[&file_name, &opt_str]);
                } else if level == 0 {
                    self.log_fail(
                        context,
                        FailureLevel::Warning,
                        "Warning_NoOptimization",
                        &[&file_name],
                    );
                } else {
                    self.log_fail(
                        context,
                        FailureLevel::Warning,
                        "Warning_LowOptimization",
                        &[&file_name, &opt_str],
                    );
                }
            }
            None => {
                self.log_not_applicable(
                    context,
                    "NotApplicable_NoDebugInfo",
                    &[&file_name],
                );
            }
        }
    }
}
