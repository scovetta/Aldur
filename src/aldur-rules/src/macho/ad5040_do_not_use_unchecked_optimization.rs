//! AD5040: DoNotUseUncheckedOptimization
//!
//! Swift binaries should not be compiled with -Ounchecked in production builds.
//! This optimization level disables runtime safety checks which can lead to undefined
//! behavior and security vulnerabilities.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::MachOBinary;
use goblin::mach::{Mach, SingleArch};

use crate::rule_ids::AD5040;

/// Symbols that indicate Swift runtime usage
const SWIFT_RUNTIME_SYMBOLS: &[&str] = &[
    "swift_", "_swift_", "$s",  // Swift 5 mangled prefix
    "_$s", // Swift 5 mangled prefix with underscore
    "$S",  // Swift 4 mangled prefix
    "_$S", // Swift 4 mangled prefix with underscore
];

/// Symbols that may indicate unchecked optimization
/// Note: Direct detection of -Ounchecked from binary is difficult.
/// We look for absence of runtime checks that would normally be present.
const SAFETY_CHECK_SYMBOLS: &[&str] = &[
    "swift_unexpectedError",
    "swift_willThrow",
    "swift_errorRetain",
    "swift_beginAccess",
    "swift_endAccess",
    "_swift_stdlib_reportFatalError",
    "_swift_stdlib_reportUnimplementedInitializer",
];

pub struct DoNotUseUncheckedOptimization {
    descriptor: RuleDescriptor,
}

impl DoNotUseUncheckedOptimization {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD5040, "DoNotUseUncheckedOptimization")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "memory-safety", "macos-only"])
            .with_short_description(
                "Swift binaries should not use -Ounchecked optimization in production.",
            )
            .with_full_description(
                "Swift applications should not be compiled with the '-Ounchecked' optimization \
                 level in production builds. This optimization level disables runtime safety \
                 checks including bounds checking, overflow detection, and type cast validation. \
                 While this can improve performance, it can also lead to undefined behavior and \
                 security vulnerabilities if the disabled checks would have caught an error. \
                 Use '-O' or '-Osize' for production builds instead.",
            )
            .with_fix_hint("Use -O2 or -Os instead of -Ounchecked for release builds")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' appears to include Swift runtime safety checks.",
            )
            .with_message(
                "Pass_NotSwift",
                "'{0}' does not appear to be a Swift binary.",
            )
            .with_message(
                "Warning_PossibleUncheckedOptimization",
                "'{0}' is a Swift binary that may be compiled with '-Ounchecked' optimization. \
                 The binary is missing expected runtime safety check symbols. If this is a \
                 production build, consider recompiling with '-O' or '-Osize' instead to \
                 preserve runtime safety checks.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }

    /// Check if the binary appears to be a Swift binary
    fn is_swift_binary(symbols: &[String]) -> bool {
        symbols.iter().any(|sym| {
            SWIFT_RUNTIME_SYMBOLS
                .iter()
                .any(|prefix| sym.starts_with(prefix))
        })
    }

    /// Check if the binary has Swift safety check symbols
    fn has_safety_checks(symbols: &[String]) -> bool {
        let safety_symbols_found = SAFETY_CHECK_SYMBOLS
            .iter()
            .filter(|check_sym| symbols.iter().any(|sym| sym.contains(*check_sym)))
            .count();

        // If we find at least some safety check symbols, the binary likely has checks enabled
        safety_symbols_found >= 2
    }

    /// Extract symbol names from a Mach-O binary
    fn get_symbols(data: &[u8]) -> Vec<String> {
        let mut symbols = Vec::new();

        if let Ok(mach) = Mach::parse(data) {
            match mach {
                Mach::Binary(macho) => {
                    // Get symbols from symbol table
                    for (name, _) in macho.symbols().flatten() {
                        symbols.push(name.to_string());
                    }
                    // Also check imports
                    if let Ok(imports) = macho.imports() {
                        for import in imports {
                            symbols.push(import.name.to_string());
                        }
                    }
                }
                Mach::Fat(fat) => {
                    // Check all architectures
                    for i in 0..fat.narches {
                        if let Ok(SingleArch::MachO(ref macho)) = fat.get(i) {
                            for (name, _) in macho.symbols().flatten() {
                                symbols.push(name.to_string());
                            }
                            if let Ok(imports) = macho.imports() {
                                for import in imports {
                                    symbols.push(import.name.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        symbols
    }
}

impl Default for DoNotUseUncheckedOptimization {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DoNotUseUncheckedOptimization {
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

        let data = macho.data();
        let symbols = Self::get_symbols(data);

        // Check if this is a Swift binary
        if !Self::is_swift_binary(&symbols) {
            self.log_pass(context, "Pass_NotSwift", &[&file_name]);
            return;
        }

        // Check for presence of safety check symbols
        if Self::has_safety_checks(&symbols) {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(
                context,
                FailureLevel::Warning,
                "Warning_PossibleUncheckedOptimization",
                &[&file_name],
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_descriptor() {
        let rule = DoNotUseUncheckedOptimization::new();
        assert_eq!(rule.descriptor().id, AD5040);
        assert_eq!(rule.descriptor().name, "DoNotUseUncheckedOptimization");
    }

    #[test]
    fn test_swift_detection() {
        let swift_symbols = vec![
            "_swift_allocObject".to_string(),
            "swift_release".to_string(),
        ];
        assert!(DoNotUseUncheckedOptimization::is_swift_binary(
            &swift_symbols
        ));

        let swift5_symbols = vec!["$s4Main3appAA0B0Vvp".to_string()];
        assert!(DoNotUseUncheckedOptimization::is_swift_binary(
            &swift5_symbols
        ));

        let non_swift_symbols = vec!["_main".to_string(), "_printf".to_string()];
        assert!(!DoNotUseUncheckedOptimization::is_swift_binary(
            &non_swift_symbols
        ));
    }

    #[test]
    fn test_safety_check_detection() {
        let safe_symbols = vec![
            "swift_unexpectedError".to_string(),
            "swift_willThrow".to_string(),
            "swift_beginAccess".to_string(),
        ];
        assert!(DoNotUseUncheckedOptimization::has_safety_checks(
            &safe_symbols
        ));

        let unsafe_symbols = vec![
            "_swift_allocObject".to_string(),
            "_swift_release".to_string(),
        ];
        assert!(!DoNotUseUncheckedOptimization::has_safety_checks(
            &unsafe_symbols
        ));
    }
}
