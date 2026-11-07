//! AWS-LC AES-256-GCM helpers for the `fips` build's sealing paths (proxy
//! context codec, login tracker). Wire format everywhere is
//! `nonce_12 || ciphertext || tag_16` with no AAD.

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

use crate::error::Error;

/// Seal `plaintext` under a 32-byte key with the caller's nonce (no AAD).
pub(crate) fn gcm_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    reason: &'static str,
) -> Result<Vec<u8>, Error> {
    let less_safe = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).map_err(|_err| {
        Error::InvalidConfiguration {
            reason: "AES-256-GCM key size mismatch",
        }
    })?);
    let mut in_out = plaintext.to_vec();
    less_safe
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(*nonce),
            Aad::empty(),
            &mut in_out,
        )
        .map_err(|_err| Error::DecryptFailed { reason })?;
    Ok(in_out)
}

/// Open a `ciphertext || tag_16` blob produced by [`gcm_seal`] under the same key.
pub(crate) fn gcm_open(
    key: &[u8; 32],
    nonce: &[u8],
    ct_with_tag: &[u8],
    reason: &'static str,
) -> Result<Vec<u8>, Error> {
    let nonce: [u8; 12] = nonce
        .try_into()
        .map_err(|_err| Error::DecryptFailed { reason })?;
    let less_safe = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).map_err(|_err| {
        Error::InvalidConfiguration {
            reason: "AES-256-GCM key size mismatch",
        }
    })?);
    let mut in_out = ct_with_tag.to_vec();
    less_safe
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::empty(),
            &mut in_out,
        )
        .map_err(|_err| Error::DecryptFailed { reason })?;
    Ok(in_out)
}
