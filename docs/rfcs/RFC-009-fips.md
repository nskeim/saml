# RFC-009: FIPS-Validated Cryptography

**Status**: Draft
**Date**: 2026-07-14

## Summary

The `fips` Cargo feature routes the crate's cryptographic primitives through
**AWS-LC** (the `aws-lc-rs` binding with its `fips` feature), the FIPS 140-3
validated module. AWS-LC is built and **linked statically into the binary**, so
the validated module ships with the crate rather than being a runtime dependency.
This RFC records what the feature covers today, how it is gated, and what is
deferred, so an operator can tell at a glance which crypto paths are FIPS-backed
and which still run on the pure-Rust fallback.

The design principle is *feature-gated, not a fork*: every routed primitive keeps
its pure-Rust implementation and is selected at compile time behind
`#[cfg(feature = "fips")]`. A default build is byte-for-byte the crate's existing
pure-Rust behavior; a `fips` build swaps in AWS-LC for the paths this RFC lists.
No public API changes and no new enum variants are introduced by the routing.

---

## 1. Scope

In scope (this RFC):

- Which primitives are routed to AWS-LC, and in which PR.
- The policy restrictions a FIPS build enforces.
- How `fips` interacts with the other crypto features (`weak-algos`,
  `artifact-binding`).

Out of scope:

- The pure-Rust implementations themselves (unchanged).
- Transport-layer TLS (rustls) — that is the caller's / `reqwest-client`'s
  concern, not this crate's.

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
| xmlenc **AES-GCM / AES-CBC** encrypt+decrypt | `xmlenc/{encrypt,decrypt}.rs` | C2 | deferred |
| **RSA-OAEP** key-transport decrypt (+ encrypt) | `crypto/keypair.rs` `decrypt_rsa_oaep`, `xmlenc/encrypt.rs` | C2 | deferred |
| **HMAC-SHA-256** NameId transform | `proxy.rs` `PersistentPerSpHmac` | C3 | deferred |
| **AES-256-GCM** proxy context codec | `proxy.rs` `Aes256GcmCodec` | C3 | deferred |

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
  and does not affect signature or key-transport crypto.

## 5. FIPS posture and the `rsa` advisory

Routing signing and verification to AWS-LC (PR B) removes the pure-Rust `rsa`
crate from those two paths in a FIPS build, which closes the
RUSTSEC-2023-0071 "Marvin Attack" timing exposure on RSA **signing** and
**verification**. The residual pure-Rust `rsa` exposure in a FIPS build is the
**RSA-OAEP key-transport decryption** path (and the `xmlenc` AES paths), which
remain on the pure-Rust backend until PR C2 routes them to AWS-LC. Until then, a
FIPS build's OAEP decryption is not FIPS-backed; see `SECURITY.md` → "Known
Advisories" for the full advisory text.

## 6. Build requirements

A `fips` build compiles AWS-LC from source (the bundled `.cmake`/`.go`), so the
build environment needs a C compiler, `cmake`, and `go`. The CI `fips` lane
installs these and runs `cargo clippy` / `cargo test` with `--features fips`.
