//! AD5015: DoNotStaticallyLinkOpenSSL
//!
//! Checks that binaries do not statically link OpenSSL.
//! Statically linked OpenSSL requires manual updates when vulnerabilities are discovered.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::MachOBinary;

use crate::rule_ids::AD5015;

/// OpenSSL-specific symbols that uniquely identify OpenSSL usage.
/// These are prefixed with OPENSSL_ or are unique to OpenSSL's implementation.
/// We avoid generic names like SHA256_Init which could match other crypto implementations.
const OPENSSL_UNIQUE_SYMBOLS: &[&str] = &[
    // OpenSSL initialization and core functions (very specific)
    "OPENSSL_init_ssl",
    "OPENSSL_init_crypto",
    "OPENSSL_sk_new_null",
    "OPENSSL_sk_push",
    "OPENSSL_cleanse",
    "OPENSSL_malloc",
    "OPENSSL_free",
    // SSL-specific functions
    "SSL_CTX_new",
    "SSL_CTX_free",
    "SSL_new",
    "SSL_free",
    "SSL_connect",
    "SSL_accept",
    "SSL_read",
    "SSL_write",
    "SSL_shutdown",
    "SSL_set_fd",
    // OpenSSL error handling
    "ERR_get_error",
    "ERR_error_string",
    "ERR_print_errors_fp",
    // X509 certificate functions
    "X509_new",
    "X509_free",
    "X509_STORE_CTX_new",
    // EVP high-level crypto API
    "EVP_CIPHER_CTX_new",
    "EVP_MD_CTX_new",
    "EVP_PKEY_new",
];

pub struct DoNotStaticallyLinkOpenSSL {
    descriptor: RuleDescriptor,
}

impl DoNotStaticallyLinkOpenSSL {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD5015, "DoNotStaticallyLinkOpenSSL")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "crypto", "macos-only"])
            .with_short_description("Do not statically link OpenSSL.")
            .with_full_description(
                "Statically linking OpenSSL means your application includes the cryptographic \
                 library directly. When OpenSSL vulnerabilities are discovered (which happens \
                 from time to time), you must rebuild and redistribute your application. Prefer using \
                 the system's dynamic OpenSSL or Apple's Security framework (CommonCrypto).",
            )
            .with_fix_hint("Use CommonCrypto/Security.framework or dynamically link OpenSSL")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' does not appear to statically link OpenSSL.",
            )
            .with_message(
                "Warning",
                "'{0}' appears to statically link OpenSSL. This requires rebuilding when \
                 OpenSSL vulnerabilities are found. Consider using dynamic linking or \
                 Apple's Security framework instead.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }
}

impl Default for DoNotStaticallyLinkOpenSSL {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DoNotStaticallyLinkOpenSSL {
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

        // Count how many OpenSSL symbols are present using exact matching
        // If multiple are found, it's likely statically linked
        let openssl_count = OPENSSL_UNIQUE_SYMBOLS
            .iter()
            .filter(|sym| macho.has_symbol_exact(sym))
            .count();

        // If we find 3+ OpenSSL symbols, it's likely statically linked
        if openssl_count >= 3 {
            self.log_fail(context, FailureLevel::Warning, "Warning", &[&file_name]);
        } else {
            self.log_pass(context, "Pass", &[&file_name]);
        }
    }
}
