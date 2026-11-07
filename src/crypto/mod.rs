//! Crypto primitives: KeyPair, X509Certificate, SignatureVerifier trait,
//! and the crate's randomness source.

#[cfg(feature = "fips")]
pub(crate) mod aead;
pub mod cert;
pub(crate) mod entropy;
pub mod keypair;
pub mod verifier;
