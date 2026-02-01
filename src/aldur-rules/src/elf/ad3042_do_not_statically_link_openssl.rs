//! AD3042: DoNotStaticallyLinkOpenSSLELF
//!
//! Checks that ELF binaries do not statically link OpenSSL.
//! Statically linked OpenSSL requires manual updates when vulnerabilities are discovered.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::ElfBinary;

use crate::rule_ids::AD3042;

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

/// Dynamic libraries that indicate OpenSSL is dynamically linked
const OPENSSL_DYNAMIC_LIBS: &[&str] = &["libssl", "libcrypto"];

pub struct DoNotStaticallyLinkOpenSSLELF {
    descriptor: RuleDescriptor,
}

impl DoNotStaticallyLinkOpenSSLELF {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD3042, "DoNotStaticallyLinkOpenSSLELF")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "crypto", "linux-only"])
            .with_short_description("Do not statically link OpenSSL.")
            .with_full_description(
                "Statically linking OpenSSL means your application includes the cryptographic \
                 library directly. When OpenSSL vulnerabilities are discovered (which happens \
                 regularly), you must rebuild and redistribute your application. Prefer using \
                 the system's dynamic OpenSSL library so security updates are applied automatically.",
            )
            .with_fix_hint("Link dynamically against system OpenSSL instead of static linking")
            .with_default_level(FailureLevel::Warning)
            .with_message(
                "Pass",
                "'{0}' does not appear to statically link OpenSSL.",
            )
            .with_message(
                "Pass_DynamicLink",
                "'{0}' uses dynamically linked OpenSSL, which will receive system security updates.",
            )
            .with_message(
                "Warning",
                "'{0}' appears to statically link OpenSSL. Statically linked OpenSSL requires \
                 manual updates when vulnerabilities are discovered. Consider dynamic linking.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            )
            .with_message(
                "NotApplicable_NoOpenSSL",
                "'{0}' does not use OpenSSL.",
            );

        Self { descriptor }
    }

    /// Check OpenSSL linking status.
    /// Returns: (has_openssl_symbols, is_dynamically_linked)
    fn check_openssl_linking(elf: &ElfBinary) -> (bool, bool) {
        // First, check if OpenSSL libraries are dynamically linked
        let is_dynamic = OPENSSL_DYNAMIC_LIBS
            .iter()
            .any(|lib| elf.links_to_library(lib));

        // Check for OpenSSL-specific symbols using exact matching to avoid
        // false positives with other crypto implementations (e.g., git's blk_SHA256_*)
        let has_openssl_symbols = elf.has_any_symbol_exact(OPENSSL_UNIQUE_SYMBOLS);

        (has_openssl_symbols, is_dynamic)
    }
}

impl Default for DoNotStaticallyLinkOpenSSLELF {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DoNotStaticallyLinkOpenSSLELF {
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
            ElfType::Core | ElfType::None | ElfType::Relocatable => {
                return (
                    AnalysisApplicability::NotApplicableToSpecifiedTarget,
                    Some("ELF is core, none, or relocatable".to_string()),
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

        let (has_openssl_symbols, is_dynamic) = Self::check_openssl_linking(elf);

        if !has_openssl_symbols && !is_dynamic {
            // No OpenSSL usage detected at all
            self.log_pass(context, "Pass", &[&file_name]);
        } else if is_dynamic {
            // OpenSSL is dynamically linked - good!
            self.log_pass(context, "Pass_DynamicLink", &[&file_name]);
        } else {
            // Has OpenSSL symbols but not dynamically linked - static linking detected
            self.log_fail(context, FailureLevel::Warning, "Warning", &[&file_name]);
        }
    }
}
