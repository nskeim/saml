# Cryptographic inventory (default / `fips` build)

Every production cryptographic **operation** under the default feature set is
routed through AWS-LC (`aws-lc-rs` + `aws-lc-fips-sys`). Key parse/encode is
outside this inventory ([BOUNDARY.md](BOUNDARY.md)).

## SAML protocol

| Operation | Call site | AWS-LC API / algorithm |
| --- | --- | --- |
| SHA-256 / 384 / 512 digest | `dsig/algorithms.rs` `DigestAlgorithm::digest` | `aws_lc_rs::digest` `SHA256` / `SHA384` / `SHA512` |
| SHA-1 digest (legacy / `weak-algos` or artifact SourceID) | `dsig/algorithms.rs`, `binding/artifact.rs` | `SHA1_FOR_LEGACY_USE_ONLY` |
| Cert SHA-256 fingerprint | `crypto/cert.rs` | via `DigestAlgorithm::Sha256.digest` |
| CSPRNG | `crypto/entropy.rs` | `SystemRandom` / `RAND_bytes` |
| RSA-PKCS#1 v1.5 sign (SHA-256/384/512) | `crypto/keypair.rs` `sign_fips` | `RSA_PKCS1_SHA*` |
| ECDSA sign P-256 / P-384 | `crypto/keypair.rs` | `ECDSA_P256/P384_*_FIXED_SIGNING` |
| RSA / ECDSA verify | `crypto/cert.rs` `verify_fips` | `UnparsedPublicKey` + `RSA_PKCS1_2048_8192_SHA*` / ECDSA FIXED+ASN1 |
| AES-128/256-CBC encrypt/decrypt | `xmlenc/{encrypt,decrypt}.rs` | `cipher` CBC PKCS7 |
| AES-128/256-GCM encrypt/decrypt | `xmlenc/{encrypt,decrypt}.rs` | `aead` `AES_*_GCM` |
| RSA-OAEP wrap/unwrap (paired digests) | `xmlenc/encrypt.rs`, `keypair.rs` | `OAEP_SHA*_MGF1SHA*` |
| HMAC-SHA-256 NameId | `proxy.rs` `PersistentPerSpHmac` | `hmac::HMAC_SHA256` |
| AES-256-GCM proxy / login-tracker / artifact seal | `crypto/aead.rs` (+ callers) | `AES_256_GCM` |

All of the above call `crypto::fips::ensure()` (or go through a helper that does)
before using the module.

## TLS (`reqwest-client`)

| Operation | Call site | Provider |
| --- | --- | --- |
| Process crypto provider install | `http.rs` `install_default_crypto_provider` | `rustls::crypto::aws_lc_rs::default_provider()` with `provider.fips() == true` |
| TLS 1.2 / 1.3 record crypto, handshake signatures, KDFs | rustls via reqwest | Same AWS-LC FIPS provider |

Hand-built `reqwest::Client` values must call `install_default_crypto_provider()`
(or equivalent) before use; `ReqwestClient::default()` does this automatically.

## Explicitly not in this inventory

- PEM/DER key and certificate **parsing** / PKCS#8 **re-encode** (RustCrypto containers).
- Test-only RSA key generation.
- Pure-Rust paths compiled only when `fips` is **off**.
- `weak-algos` residuals (RSA-SHA1 sign/verify, PKCS#1 v1.5 key transport) if a
  hand-built policy enables them under `fips` — see BOUNDARY.md.
