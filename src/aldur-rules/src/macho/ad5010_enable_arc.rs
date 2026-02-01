//! AD5010: EnableAutomaticReferenceCounting
//!
//! Checks that Objective-C Mach-O binaries use Automatic Reference Counting (ARC).
//! ARC provides memory safety by automatically managing object lifetimes.
//! Manual memory management is error-prone and can lead to use-after-free vulnerabilities.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::MachOBinary;

use crate::rule_ids::AD5010;

/// ARC symbols that indicate Automatic Reference Counting is enabled
const ARC_SYMBOLS: &[&str] = &[
    "objc_retain",
    "objc_release",
    "objc_autorelease",
    "objc_retainAutoreleasedReturnValue",
    "objc_retainBlock",
    "objc_autoreleaseReturnValue",
    "objc_autoreleasePoolPush",
    "objc_loadWeakRetained",
    "objc_loadWeak",
    "objc_destroyWeak",
    "objc_storeWeak",
    "objc_initWeak",
    "objc_moveWeak",
    "objc_copyWeak",
    "objc_retainedObject",
    "objc_unretainedObject",
    "objc_unretainedPointer",
];

/// Symbols that indicate Objective-C is in use (required for ARC check to be relevant)
const OBJC_SYMBOLS: &[&str] = &[
    "objc_msgSend",
    "objc_msgSendSuper",
    "objc_getClass",
    "objc_allocWithZone",
    "objc_alloc",
];

/// Xamarin-related symbols (ARC check doesn't apply to Xamarin)
const XAMARIN_SYMBOLS: &[&str] = &[
    "xamarin",
    "monotouch",
    "mono_",
];

pub struct EnableAutomaticReferenceCounting {
    descriptor: RuleDescriptor,
}

impl EnableAutomaticReferenceCounting {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD5010, "EnableAutomaticReferenceCounting")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "memory-safety", "macos-only"])
            .with_short_description("Enable Automatic Reference Counting (ARC) for Objective-C.")
            .with_full_description(
                "Automatic Reference Counting (ARC) is a compiler feature that automatically \
                 manages Objective-C object lifetimes. This eliminates entire classes of \
                 memory safety bugs including use-after-free and double-free vulnerabilities. \
                 Enable ARC by compiling with '-fobjc-arc' flag. All modern iOS and macOS \
                 development should use ARC.",
            )
            .with_fix_hint("Compile Objective-C code with -fobjc-arc")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' uses Automatic Reference Counting (ARC).",
            )
            .with_message(
                "Warning",
                "'{0}' appears to use Objective-C without Automatic Reference Counting (ARC). \
                 Manual memory management is error-prone and can lead to security vulnerabilities. \
                 Compile with '-fobjc-arc' to enable ARC.",
            )
            .with_message(
                "NotApplicable_NotObjC",
                "'{0}' does not appear to use Objective-C.",
            )
            .with_message(
                "NotApplicable_Xamarin",
                "'{0}' is a Xamarin application. ARC check does not apply.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for EnableAutomaticReferenceCounting {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnableAutomaticReferenceCounting {
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

        // Check if this is a Xamarin app (ARC doesn't apply)
        if macho.has_any_symbol(XAMARIN_SYMBOLS) {
            self.log_not_applicable(context, "NotApplicable_Xamarin", &[&file_name]);
            return;
        }

        // Check if this binary uses Objective-C
        if !macho.has_any_symbol(OBJC_SYMBOLS) {
            self.log_not_applicable(context, "NotApplicable_NotObjC", &[&file_name]);
            return;
        }

        // Check for ARC symbols
        if macho.has_any_symbol(ARC_SYMBOLS) {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(context, FailureLevel::Warning, "Warning", &[&file_name]);
        }
    }
}
