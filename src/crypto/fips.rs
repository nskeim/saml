//! FIPS-mode runtime assertion (compiled only under the `fips` feature).
//!
//! A `fips` build statically links AWS-LC built in FIPS mode. This module
//! provides an explicit, cached way to assert that the loaded module is
//! actually in FIPS mode, so a build mistake (e.g. linking `aws-lc-rs`
//! without its `fips` feature) fails closed instead of silently running
//! non-FIPS crypto.

use std::sync::OnceLock;

/// The one-shot FIPS-mode check result, cached after first use.
static CHECK: OnceLock<Result<(), &'static str>> = OnceLock::new();

/// Check whether the linked AWS-LC module is in FIPS mode.
///
/// Runs `aws_lc_rs::try_fips_mode()` once and caches the result. Returns
/// `Ok(())` when the module is in FIPS mode, or `Err(reason)` with a static
/// message (e.g. `"FIPS mode not enabled!"`) when it is not.
pub(crate) fn check() -> Result<(), &'static str> {
    *CHECK.get_or_init(aws_lc_rs::try_fips_mode)
}

/// Fail closed if the module is not in FIPS mode.
///
/// Aborts the process (matching the entropy-source failure policy in
/// `crate::crypto::entropy`) rather than continuing with non-FIPS crypto.
/// Called as a backstop at the top of every AWS-LC crypto entry point
/// (digest, sign, verify, entropy, AEAD, AES-CBC, RSA-OAEP, HMAC, and the
/// artifact SourceID SHA-1), so a deployment that never calls the public
/// `assert_fips_mode()` still fails closed on first crypto use.
pub(crate) fn ensure() {
    if check().is_err() {
        std::process::abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `fips` build links AWS-LC in FIPS mode, so the one-shot check and the
    /// public assertion must both succeed. (The `ensure()` abort path needs a
    /// non-FIPS `aws-lc-rs` build and is not exercised here.)
    #[test]
    fn fips_build_reports_fips_mode() {
        assert!(matches!(check(), Ok(())));
        assert!(matches!(crate::assert_fips_mode(), Ok(())));
    }
}
