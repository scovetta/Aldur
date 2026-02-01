//! AD2044: DoNotStaticallyLinkOpenSSLPE
//!
//! Checks that PE binaries do not statically link OpenSSL.
//! Statically linked OpenSSL requires manual updates when vulnerabilities are discovered.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel, Rule, RuleCategory,
    RuleDescriptor,
};
use aldur_parsers::PeBinary;

use crate::rule_ids::AD2044;

/// Symbols that indicate OpenSSL is statically linked
const OPENSSL_STATIC_SYMBOLS: &[&str] = &[
    "OPENSSL_init_ssl",
    "SSL_CTX_new",
    "SSL_new",
    "SSL_connect",
    "SSL_read",
    "SSL_write",
    "EVP_EncryptInit",
    "EVP_DecryptInit",
    "RSA_new",
    "RSA_generate_key_ex",
    "AES_encrypt",
    "SHA256_Init",
    "SHA256_Update",
    "SHA256_Final",
    "CRYPTO_malloc",
    "OPENSSL_cleanse",
];

/// DLL references that indicate dynamic linking
const OPENSSL_DLL_PATTERNS: &[&str] = &["libssl", "libcrypto", "ssleay32", "libeay32"];

pub struct DoNotStaticallyLinkOpenSSLPE {
    descriptor: RuleDescriptor,
}

impl DoNotStaticallyLinkOpenSSLPE {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD2044, "DoNotStaticallyLinkOpenSSLPE")
            .with_category(RuleCategory::Security)
            .with_tags(&["recommended", "crypto", "windows-only"])
            .with_short_description("Do not statically link OpenSSL.")
            .with_full_description(
                "Statically linking OpenSSL means your application includes the cryptographic \
                 library directly. When OpenSSL vulnerabilities are discovered (which happens \
                 regularly), you must rebuild and redistribute your application. Prefer using \
                 dynamically linked OpenSSL or platform-native cryptography (CNG/CAPI) on Windows.",
            )
            .with_fix_hint("Use CNG/CAPI or dynamically link OpenSSL")
            .with_default_level(FailureLevel::Warning)
            .with_message("Pass", "'{0}' does not appear to statically link OpenSSL.")
            .with_message(
                "Pass_DynamicLink",
                "'{0}' uses dynamically linked OpenSSL DLLs.",
            )
            .with_message(
                "Warning",
                "'{0}' appears to statically link OpenSSL. Statically linked OpenSSL requires \
                 manual updates when vulnerabilities are discovered. Consider dynamic linking \
                 or using Windows CNG/CAPI.",
            )
            .with_message(
                "NotApplicable_InvalidMetadata",
                "'{0}' was not evaluated for check '{1}' as the analysis is not relevant \
                 based on observed metadata: {2}.",
            );

        Self { descriptor }
    }

    /// Check if OpenSSL is statically linked
    fn check_openssl_linking(pe: &PeBinary) -> (bool, bool) {
        // Check if any OpenSSL DLLs are in the import table
        let imported_dlls = pe.imported_dlls();
        let has_dynamic_openssl = imported_dlls.iter().any(|dll| {
            let dll_lower = dll.to_lowercase();
            OPENSSL_DLL_PATTERNS
                .iter()
                .any(|pattern| dll_lower.contains(pattern))
        });

        if has_dynamic_openssl {
            return (false, true); // Not statically linked, dynamic found
        }

        // Check for OpenSSL export symbols that would indicate static linking
        // When statically linked, these functions would be exported or present as internal symbols
        let exports = pe.exported_symbols();
        let has_static_exports = exports.iter().any(|sym| {
            OPENSSL_STATIC_SYMBOLS
                .iter()
                .any(|pattern| sym.contains(pattern))
        });

        (has_static_exports, false)
    }
}

impl Default for DoNotStaticallyLinkOpenSSLPE {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DoNotStaticallyLinkOpenSSLPE {
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

        let (is_static, has_dynamic) = Self::check_openssl_linking(pe);

        if has_dynamic {
            self.log_pass(context, "Pass_DynamicLink", &[&file_name]);
        } else if is_static {
            self.log_fail(context, FailureLevel::Warning, "Warning", &[&file_name]);
        } else {
            self.log_pass(context, "Pass", &[&file_name]);
        }
    }
}
