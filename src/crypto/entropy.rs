//! Randomness source.
//!
//! Without the `fips` feature, randomness comes from the OS CSPRNG via
//! `rand` / `OsRng`. With `fips`, it comes from AWS-LC's FIPS-validated
//! randomness (OS entropy source via `RAND_bytes`, exposed as
//! `aws_lc_rs::rand::SystemRandom`).

/// Fill `buf` with random bytes, failing rather than panicking if the
/// entropy source is unavailable. Callers map the failure to their own
/// error variant so the reason string stays specific.
pub(crate) fn try_fill_random(buf: &mut [u8]) -> Result<(), ()> {
    #[cfg(feature = "fips")]
    {
        use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
        SystemRandom::new().fill(buf).map_err(|_err| ())
    }
    #[cfg(not(feature = "fips"))]
    {
        use rsa::rand_core::{OsRng, RngCore as _};
        OsRng.try_fill_bytes(buf).map_err(|_err| ())
    }
}

/// Fill `buf` with random bytes, failing closed if the entropy source is
/// unavailable. For call sites whose existing contract is a panicking
/// `fill_bytes` (opaque identifiers and session indices, where failing
/// closed buys nothing). Under `fips` there is no non-FIPS fallback: an
/// entropy-source failure aborts the process, so it cannot be recovered from.
pub(crate) fn fill_random(buf: &mut [u8]) {
    if try_fill_random(buf).is_err() {
        #[cfg(feature = "fips")]
        std::process::abort();
        #[cfg(not(feature = "fips"))]
        {
            use rand::RngCore as _;
            rand::rng().fill_bytes(buf);
        }
    }
}
