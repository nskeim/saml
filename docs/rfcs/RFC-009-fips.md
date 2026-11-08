# RFC-009: AWS-LC FIPS Module-Backed Cryptography

**Status**: Draft
**Date**: 2026-07-14

## Summary

The `fips` Cargo feature routes the crate's cryptographic *operations* through
**AWS-LC** (the `aws-lc-rs` binding with its `fips` feature), a FIPS 140-3
validated cryptographic module. AWS-LC is built and **linked statically into
the binary**, so the validated module ships with the crate rather than being a
runtime dependency. **In this fork, `fips` is part of the Cargo `default`
feature set**, so a plain `cargo build` is a FIPS build. Pure-Rust behavior
remains available via `--no-default-features` without `fips`.

With `reqwest-client` (also default), TLS uses rustls with the AWS-LC FIPS
`CryptoProvider` installed by `ReqwestClient::default` /
`install_default_crypto_provider()`.

This does **not** make the `saml` crate itself FIPS-validated or CMVP-certified.
Only cryptographic modules receive FIPS certificates; this crate is an
application of that module. Operators who need a FIPS-compliant deployment must
still treat key provenance and any `weak-algos` policy overrides as separate
boundary decisions (see §1, §7, and `docs/fips/`).

The design principle is *feature-gated, not a fork*: every routed primitive keeps
its pure-Rust implementation and is selected at compile time behind
`#[cfg(feature = "fips")]`. No public API changes and no new enum variants are
introduced by the routing. Auditor-facing evidence lives in `docs/fips/` and
`./scripts/fips-evidence.sh`.

---

## 1. Scope

In scope (this RFC):

- Which primitives are routed to AWS-LC, and in which PR.
- The policy restrictions a FIPS build enforces.
- How `fips` interacts with the other crypto features (`weak-algos`,
  `artifact-binding`).
- Runtime FIPS-mode assertion coverage.
- Explicit cryptographic boundary: what remains outside AWS-LC.

Out of scope:

- The pure-Rust implementations themselves (unchanged).
- **CMVP certification of this crate** — impossible and not claimed; validation
  attaches to AWS-LC.
- **Key lifecycle parse/encode** — PEM/DER load and PKCS#8 re-encode still use
  RustCrypto containers (`rsa` / `p256` / `p384`) before material is imported
  into AWS-LC for crypto ops. See §7.
- **Example apps' own HTTP clients** — only `saml::ReqwestClient` is covered
  by the crate TLS claim; demos may declare separate `reqwest` deps.

## 2. What is routed

Routing lands across three PRs. As of this RFC:

| Primitive | Site | PR | Status |
| --- | --- | --- | --- |
| Digests (SHA-256/384/512, SHA-1 for legacy) | `dsig/algorithms.rs` `DigestAlgorithm::digest` | A | routed |
| Certificate SHA-256 fingerprint | `crypto/cert.rs` | A | routed |
| Randomness (all RNG call sites) | `crypto/entropy.rs` `try_fill_random` / `fill_random` | A | routed |
| xmlenc AES key/IV/nonce randomness | `xmlenc/encrypt.rs` | A | routed (via `entropy`) |
| RSA / ECDSA **signing** | `crypto/keypair.rs` `KeyPair::sign` | B | routed |
| RSA / ECDSA **verification** (incl. `DefaultVerifier`, certificate binding) | `crypto/cert.rs` `PublicKey::verify_signature` | B | routed |
| xmlenc **AES-GCM / AES-CBC** encrypt+decrypt | `xmlenc/{encrypt,decrypt}.rs` | C2 | routed |
| **RSA-OAEP** key-transport decrypt (+ encrypt) | `crypto/keypair.rs` `decrypt_rsa_oaep`, `xmlenc/encrypt.rs` | C2 | routed |
| **HMAC-SHA-256** NameId transform | `proxy.rs` `PersistentPerSpHmac` | C3 | routed |
| **AES-256-GCM** proxy context codec | `proxy.rs` `Aes256GcmCodec` | C3 | routed |
| **AES-256-GCM** login tracker seal/open | `sp.rs` `LoginTrackerPayload` | C4 | routed |
| **AES-256-GCM** artifact transaction seal/open | `idp.rs` `ArtifactResolveTransaction` | C5 | routed |

The reference digest (`dsig/reference.rs`) and the certificate fingerprint both
call `DigestAlgorithm::digest`, so they are FIPS-backed transitively from PR A —
no separate routing was needed.

### Signing and verification (PR B)

- **Sign.** `KeyPair` lazily builds an AWS-LC signer from the stored PKCS#8
  secret and caches it in a `Mutex<Option<_>>` (so `Clone` stays cheap). RSA uses
  `RSA_PKCS1_SHA{256,384,512}`; ECDSA uses the `_FIXED_SIGNING` algorithms, which
  emit P1363 `r||s` — the same byte format the pure-Rust path produced, so
  signatures are interchangeable between builds.
- **Verify.** `PublicKey` stores the SPKI DER and verifies via
  `UnparsedPublicKey` with `RSA_PKCS1_2048_8192_SHA*` and the ECDSA
  `_FIXED`/`_ASN1` verification algorithms (P1363 first, ASN.1 fallback). This is
  the path `DefaultVerifier` and the certificate-binding cross-check both take,
  so no verifier plumbing changed.

### Key generation

There is **no public key-generation API** in this crate — keys are loaded from
PEM/DER. The only keygen is test scaffolding, which stays pure-Rust. Nothing to
route.

## 3. Policy restrictions under `fips`

A FIPS build enforces the following at validation time (before any crypto runs):

- **Unpaired RSA-OAEP is rejected.** AWS-LC supports only *paired* OAEP — the
  label hash and the MGF1 hash must be the same digest (SHA-1+MGF1-SHA1,
  SHA-256+MGF1-SHA256, SHA-384+MGF1-SHA384, SHA-512+MGF1-SHA512). The two OAEP
  allow-lists in `PeerCryptoPolicy` remain independent (so a peer can permit
  SHA-256 + MGF1-SHA1 without permitting SHA-1 as a message digest); the pairing
  itself is checked at `xmlenc/decrypt.rs` and returns
  `Error::DisallowedAlgorithm`.
- **RSA < 2048-bit is rejected at verify time.** AWS-LC enforces the FIPS 186
  minimum RSA key size when loading a verification key, so sub-2048-bit keys
  (e.g. the legacy ADFS 1024-bit fixtures) fail verification under `fips`. This
  is enforced by the module, not re-checked at the policy layer.

## 4. Interaction with other features

- **`weak-algos`.** This feature enables SHA-1 signatures/digests and RSA-PKCS1
  v1.5 key transport — all disallowed by FIPS. Under `fips`, **`weak-algos` is
  ignored for the default policy**: `PeerCryptoPolicy::strong_defaults()` never
  lists SHA-1 or PKCS1-v1.5, so a FIPS build's default posture is FIPS-compliant
  regardless of whether `weak-algos` is compiled in. The SHA-1 / PKCS1-v1.5 code
  paths still *compile* (and are reachable only if an operator explicitly allows
  them in a hand-built per-peer policy), so `fips,weak-algos` is not a build
  error — the FIPS guarantee for those paths is soft, and operators who need a
  hard guarantee should not enable `weak-algos`.
- **`artifact-binding`.** Independent of `fips`; it enables SHA-1 for the
  artifact `SourceID` routing tag only (a collision misroutes rather than forges)
  and does not affect signature or key-transport crypto. Under `fips` that SHA-1
  still runs through AWS-LC's legacy digest API.

## 5. FIPS posture and the `rsa` advisory

Routing signing and verification to AWS-LC (PR B) removes the pure-Rust `rsa`
crate from those two paths in a FIPS build, which closes the
RUSTSEC-2023-0071 "Marvin Attack" timing exposure on RSA **signing** and
**verification**. PRs C2, C3, C4 and C5 route the remaining paths — xmlenc
AES-GCM/CBC, RSA-OAEP key transport, the proxy HMAC-SHA-256 / AES-256-GCM
codec, and the login-tracker and artifact-transaction AES-256-GCM seals — to
AWS-LC as well, so a FIPS build's default posture runs every crypto *operation*
on the validated module. The only pure-Rust `rsa` *crypto* still reachable in a
FIPS build is the legacy RSA-PKCS#1-v1.5 key-transport path, which `weak-algos`
gates and the default policy refuses; see `SECURITY.md` → "Known Advisories"
for the full advisory text. Key parse/encode still uses RustCrypto (§7).

### Runtime FIPS-mode assertion

A FIPS build must actually *run* the validated module, not just link it.
`assert_fips_mode()` (public) checks at startup that the linked AWS-LC module
is in FIPS mode and fails closed otherwise, catching a build mistake (e.g.
`aws-lc-rs` linked without its `fips` feature). The same check runs as a
fail-closed backstop on **every** AWS-LC crypto entry point — digests, sign,
verify, entropy, AEAD seals, AES-CBC, RSA-OAEP, HMAC, and artifact SourceID —
so a deployment that never calls the startup check still refuses to run
non-FIPS crypto. See `SECURITY.md` → "FIPS Mode" for the operator-facing
description.

## 6. Build requirements

A `fips` build compiles AWS-LC from source (the bundled `.cmake`/`.go`), so the
build environment needs a C compiler, `cmake`, and `go`. The dependency is
declared with `default-features = false` so only `aws-lc-fips-sys` is pulled,
not the non-FIPS `aws-lc-sys`. The CI `fips` lane installs cmake/go and runs
`cargo clippy` / `cargo test` with `--features fips`.

## 7. Key lifecycle boundary (out of cryptographic module scope)

Under `fips`, keys are still **parsed and held** as RustCrypto types
(`rsa::RsaPrivateKey`, `p256`/`p384` signing keys, etc.) and re-encoded to
PKCS#8 / SPKI DER before import into AWS-LC for signing, verification, and
OAEP. That parse/encode path is:

- **Not** a FIPS-approved cryptographic service in the CMVP sense.
- **Documented as outside the validated-module boundary** for this crate's
  FIPS posture: the cryptographic *operations* (sign, verify, encrypt, decrypt,
  MAC, digest, RNG) run on AWS-LC; containerization of key material before
  import does not.
- Unchanged by design for now — migrating parse/hold entirely onto AWS-LC
  key types is deferred. Operators who require keys never to touch non-module
  code should inject keys via a custom `SignatureVerifier` / HSM-backed path
  (RFC-002 §4) rather than PEM load through `KeyPair`.

Test-only RSA key generation remains pure-Rust and is not part of the
production API.

## 8. TLS (ReqwestClient)

Under `fips` + `reqwest-client` (the default):

| Layer | Backend |
| --- | --- |
| XML-DSig / xmlenc / seals / HMAC / RNG | AWS-LC FIPS module |
| `ReqwestClient` TLS | rustls + `aws_lc_rs` provider with `CryptoProvider::fips() == true` |

`reqwest` is built with `rustls-tls-webpki-roots-no-provider`. At
`ReqwestClient::default` (and `install_default_crypto_provider`), the process
asserts AWS-LC FIPS mode and installs the aws-lc-rs rustls provider. Without
`fips`, the same entry points install the ring provider instead.

Operators who bring their own `reqwest::Client` must call
`install_default_crypto_provider()` (or equivalent) first. Call
`saml::assert_fips_mode()` at process startup and treat failure as a hard
deploy error. Do not enable `weak-algos` unless an exception process accepts
the pure-Rust residual paths.
