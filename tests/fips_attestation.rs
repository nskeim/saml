//! Runtime attestation that the default / `fips` build is using the AWS-LC
//! FIPS module for SAML crypto and (when `reqwest-client` is on) rustls TLS.
//!
//! Gated with `required-features = ["fips"]` in Cargo.toml.

#![cfg(feature = "fips")]

mod common;

use saml::SignatureAlgorithm;
use saml::crypto::cert::X509Certificate;
use saml::crypto::keypair::KeyPair;

#[test]
fn aws_lc_reports_fips_mode() {
    let result = aws_lc_rs::try_fips_mode();
    assert!(
        matches!(result, Ok(())),
        "aws_lc_rs::try_fips_mode failed: {result:?}"
    );
}

#[test]
fn assert_fips_mode_succeeds() {
    saml::assert_fips_mode().unwrap_or_else(|err| panic!("assert_fips_mode: {err}"));
}

#[test]
fn digest_and_sign_use_fips_module() {
    // Fingerprint + sign both call `fips::ensure()` then AWS-LC.
    let cert = X509Certificate::from_pem(common::RSA_CERT_PEM)
        .unwrap_or_else(|err| panic!("cert: {err}"));
    let fp = cert.fingerprint_sha256();
    assert_eq!(fp.len(), 32);

    let key = KeyPair::from_pkcs8_pem(common::RSA_KEY_PKCS8_PEM)
        .unwrap_or_else(|err| panic!("key: {err}"));
    let sig = key
        .sign(SignatureAlgorithm::RsaSha256, b"fips-attestation")
        .unwrap_or_else(|err| panic!("sign under FIPS: {err}"));
    assert_ne!(sig.len(), 0);
    cert.public_key()
        .verify_signature(SignatureAlgorithm::RsaSha256, b"fips-attestation", &sig)
        .unwrap_or_else(|err| panic!("verify under FIPS: {err}"));
}

#[cfg(feature = "reqwest-client")]
#[test]
fn rustls_provider_is_fips() {
    saml::install_default_crypto_provider();
    let provider = rustls::crypto::CryptoProvider::get_default()
        .unwrap_or_else(|| panic!("rustls CryptoProvider installed"));
    assert!(
        provider.fips(),
        "installed rustls CryptoProvider must report FIPS mode for default TLS"
    );
    // Constructing the default client re-installs (no-op) and must not abort.
    let _ = saml::ReqwestClient::default();
}
