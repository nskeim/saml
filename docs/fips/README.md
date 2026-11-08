# FIPS posture (this fork)

This fork of `saml` **defaults** to FIPS-module-backed cryptography:

- **SAML protocol crypto** (digests, RSA/ECDSA sign & verify, xmlenc AES-GCM/CBC,
  RSA-OAEP, HMAC, AEAD seals, RNG) runs on the FIPS 140-3 validated **AWS-LC**
  module via `aws-lc-rs` with its `fips` feature.
- **TLS** for the optional `ReqwestClient` (`reqwest-client` feature) uses
  rustls with the **AWS-LC FIPS** `CryptoProvider` installed at client
  construction.

This does **not** CMVP-certify the `saml` crate. Only AWS-LC is the validated
cryptographic module. See [CMVP.md](CMVP.md) and [BOUNDARY.md](BOUNDARY.md).

## Default compile flags

```text
default = [
  reqwest-client, rsa-sha, ecdsa-sha, xmlenc,
  slo, metadata-emit, xsd-validate, fips,
]
```

Equivalent: `cargo build` / `cargo test` with no feature flags.

**Build requirements:** C compiler, `cmake`, and `go` (AWS-LC FIPS is compiled
from source and statically linked).

## Operator checklist

1. Build with defaults (or explicitly `--features fips,reqwest-client,…`).
2. Call `saml::assert_fips_mode()` at process startup (also enforced on first
   crypto use and when constructing `ReqwestClient::default()`).
3. Prefer `ReqwestClient::default()` for back-channel HTTP, or call
   `saml::install_default_crypto_provider()` before building a custom
   `reqwest::Client`.
4. Collect evidence with `./scripts/fips-evidence.sh` (see [ATTESTATION.md](ATTESTATION.md)).
5. Do **not** enable `weak-algos` unless an exception process accepts the
   residual pure-Rust paths documented in [BOUNDARY.md](BOUNDARY.md).

## Pure-Rust / non-FIPS opt-out

Non-FIPS implementations remain in the tree. To build them:

```sh
cargo build -p saml --no-default-features \
  --features reqwest-client,rsa-sha,ecdsa-sha,xmlenc,slo,metadata-emit,xsd-validate
```

That build uses RustCrypto for SAML crypto and the rustls **ring** provider for
`ReqwestClient` TLS.

## Document index

| Doc | Contents |
| --- | --- |
| [CRYPTO_INVENTORY.md](CRYPTO_INVENTORY.md) | SAML + TLS ops → AWS-LC APIs |
| [BOUNDARY.md](BOUNDARY.md) | In / out of the FIPS claim |
| [CMVP.md](CMVP.md) | Module validation references |
| [ATTESTATION.md](ATTESTATION.md) | How to produce and read evidence |
| [RFC-009](../rfcs/RFC-009-fips.md) | Design record for the `fips` feature |
| [SECURITY.md](../../SECURITY.md) | Operator-facing security policy |
