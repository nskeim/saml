# FIPS claim boundary

## What we claim (default build)

Under the default Cargo features (including `fips` and `reqwest-client`):

1. SAML cryptographic **operations** listed in [CRYPTO_INVENTORY.md](CRYPTO_INVENTORY.md)
   execute on the FIPS 140-3 validated AWS-LC module.
2. `ReqwestClient::default()` installs a rustls `CryptoProvider` whose
   `fips()` method returns true (AWS-LC FIPS).
3. `saml::assert_fips_mode()` / `aws_lc_rs::try_fips_mode()` succeed, and
   every AWS-LC entry point fail-closes via `fips::ensure()` if they would not.

## What we do **not** claim

| Topic | Status |
| --- | --- |
| CMVP certificate for the `saml` crate | **Not claimed.** Only AWS-LC is a validated module. |
| Key lifecycle parse / PKCS#8 re-encode | Outside module boundary; RustCrypto containers still used before AWS-LC import. |
| Product / deployment FIPS authorization | Operator responsibility (roots, config, hosting, policies). |
| NIST TLS protocol-level recommendations beyond rustls+AWS-LC defaults | Review `ClientConfig::fips()` / deployment TLS policy separately. |
| `weak-algos` + hand-built `PeerCryptoPolicy` | Can reopen pure-Rust RSA-SHA1 / PKCS#1 v1.5; default policy refuses them. |
| Example apps' own `reqwest` deps | Demo/IdP examples may still declare their own HTTP clients; SAML crate TLS claim covers `saml::ReqwestClient` only. |

## Dependency graph caveat

Enabling `rustls/fips` currently also activates rustls's `aws_lc_rs` feature,
which may pull **`aws-lc-sys`** into the Cargo graph alongside
**`aws-lc-fips-sys`**. Runtime selection prefers the FIPS sys crate when the
`fips` feature is on; attestation is **`try_fips_mode()` / `CryptoProvider::fips()`**,
not “`aws-lc-sys` absent from `cargo tree`.”

The evidence script records whether `aws-lc-sys` appears and still **requires**
FIPS mode to succeed.

## Non-FIPS retention

`#[cfg(not(feature = "fips"))]` pure-Rust implementations remain. Building
without `fips` (see [README.md](README.md)) is supported and covered by CI's
non-FIPS opt-out arm. Removing those paths is explicitly out of scope for this
fork's FIPS work.
