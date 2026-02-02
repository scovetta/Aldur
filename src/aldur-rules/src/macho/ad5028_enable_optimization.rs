//! AD5028: EnableOptimizationMachO
//!
//! Checks that Mach-O binaries are compiled with at least -O2 optimization.
//! Unoptimized binaries may have security issues and performance problems.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::{DwarfInfo, MachOBinary};

use crate::rule_ids::AD5028;

pub struct EnableOptimizationMachO {
    descriptor: RuleDescriptor,
}

impl EnableOptimizationMachO {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD5028, "EnableOptimizationMachO")
            .with_category(RuleCategory::Performance)
            .with_tags(&["recommended", "macos-only"])
            .with_short_description(
                "Enable compiler optimization (-O2 or higher) for Mach-O binaries.",
            )
            .with_full_description(
                "Production binaries should be compiled with optimization level -O2 or higher. \
                 Unoptimized (-O0) or minimally optimized (-O1) code may have security issues \
                 that optimization eliminates, such as stack usage patterns that increase \
                 vulnerability to buffer overflows. Optimization also enables security features \
                 like FORTIFY_SOURCE to work correctly.",
            )
            .with_fix_hint("Compile with -O2 or -O3")
            .with_default_level(FailureLevel::Warning)
            .with_message("Pass", "'{0}' was compiled with optimization level {1}.")
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
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }

    /// Check optimization level from DWARF
    fn check_optimization(macho: &MachOBinary) -> Option<i32> {
        if let Ok(dwarf_info) = DwarfInfo::parse(macho.data())
            && dwarf_info.has_debug_info
            && !dwarf_info.compilation_units.is_empty()
        {
            // Check for optimization flags
            if dwarf_info.has_flag("-O3") || dwarf_info.has_flag("-Ofast") {
                return Some(3);
            }
            if dwarf_info.has_flag("-O2") || dwarf_info.has_flag("-Os") {
                return Some(2);
            }
            if dwarf_info.has_flag("-O1") {
                return Some(1);
            }
            if dwarf_info.has_flag("-O0") {
                return Some(0);
            }

            // Check optimization level from compilation units
            for cu in &dwarf_info.compilation_units {
                if let Some(ref opt_level_str) = cu.parsed_info.optimization_level {
                    // Parse the optimization level string (e.g., "-O2" -> 2)
                    if opt_level_str.contains("O3") || opt_level_str.contains("Ofast") {
                        return Some(3);
                    }
                    if opt_level_str.contains("O2") || opt_level_str.contains("Os") {
                        return Some(2);
                    }
                    if opt_level_str.contains("O1") {
                        return Some(1);
                    }
                    if opt_level_str.contains("O0") {
                        return Some(0);
                    }
                }
            }
        }
        None
    }
}

impl Default for EnableOptimizationMachO {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableOptimizationMachO {
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

        match Self::check_optimization(macho) {
            Some(level @ 2..) => {
                let level_str = format!("-O{}", level);
                self.log_pass(context, "Pass", &[&file_name, &level_str]);
            }
            Some(1) => {
                self.log_fail(
                    context,
                    FailureLevel::Warning,
                    "Warning_LowOptimization",
                    &[&file_name, "-O1"],
                );
            }
            Some(_) => {
                self.log_fail(
                    context,
                    FailureLevel::Warning,
                    "Warning_NoOptimization",
                    &[&file_name],
                );
            }
            None => {
                self.log_not_applicable(context, "NotApplicable_NoDebugInfo", &[&file_name]);
            }
        }
    }
}
