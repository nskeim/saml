# Security Policy

## Reporting a Vulnerability

Please report suspected security vulnerabilities by email to
**daniel@speakeasy.com**. Use the subject line `[saml] security report`.

Do **not** open a public GitHub issue, pull request, or discussion thread for
security-sensitive reports — the crate's threat model includes hostile peers
on the SAML wire, and a public report tips them off before downstream callers
can update.

A report ideally includes:

- The affected crate version (or commit hash).
- A minimal reproduction — SAML message bytes, fixture metadata, the call site
  triggering the issue, and the observed vs. expected behavior.
- Your assessment of impact (e.g. signature bypass, XSW, replay, panic /
  denial-of-service on the host process, parser crash).
- Any constraints on disclosure timing (see below).

You will receive an acknowledgement within 72 hours.

## Supported Versions

While the crate is pre-alpha, only the most recent `0.0.1-alpha.x` release
line receives security fixes. Older `0.0.1-alpha.N-1` releases are not
patched — upgrade to the latest `0.0.1-alpha.*` to pick up the fix.

| Version | Supported |
| --- | --- |
| `0.0.1-alpha.x` (latest) | yes |
| anything older | no |

Once the crate reaches `0.1.0`, this table will be revised to follow the
standard "current minor + previous minor" policy.

## Threat Model

The crate is designed to defend the SP / IdP / proxy roles against a hostile
SAML peer on the wire. The following classes are explicitly in scope:

- **XML Signature Wrapping (XSW)** — duplicate `ID` attributes are rejected at
  parse time; the `Reference URI` resolves to a unique `ElementId`; validated
  payload extraction is bound to the `VerifiedSignature` handle, not to a
  name lookup. There is no API path that returns a "validated" payload
  distinct from the signed payload.
- **Replay** — `ConsumeResponse::replay_cache` exposes a `ReplayCache` trait
  with an in-memory default. Assertion `ID` deduplication is performed after
  signature verification so malformed payloads cannot pollute the store.
- **Weak-crypto downgrade** — SHA-1 signature and digest algorithms
  (RSA-SHA1, DSA-SHA1, `DigestAlgorithm::Sha1`) and RSA-PKCS1-v1.5 key
  transport are gated behind the `weak-algos` Cargo feature, off by default.
  The per-peer `PeerCryptoPolicy` allow-list still gates acceptance at
  validation time even when `weak-algos` is compiled in. The `sha1` crate
  itself is not a proxy for this: `artifact-binding` enables it independently
  for the artifact `SourceID` (SAML 2.0 Bindings §3.6.4), a routing tag where
  a collision misroutes rather than forges. Audit the enabled Cargo features
  rather than the dependency graph.
- **Signature wrapping via transforms** — the XML-DSig `Transform` allow-list
  rejects XSLT, XPath, and base64 transforms. Multi-`Reference` signatures
  are rejected by default.
- **XXE / billion-laughs / DTD injection** — DTDs, internal entities, and
  processing instructions are rejected at parse time.
- **Schema-shape exploits** — inbound messages pass through an internal
  XSD-style structural validator (`xsd-validate` feature, on by default)
  before any crypto operation runs.
- **Clock-skew abuse** — `NotBefore` / `NotOnOrAfter` checks take an explicit
  `now: SystemTime` and `clock_skew: Duration`. No method silently reads the
  wall clock.
- **HTTP-Redirect detached signatures** — verified via a distinct entry
  point with the same `allowed_algorithms` discipline as XML-DSig.

The following are **out of scope** — protect against them at a higher layer:

- **Denial-of-service against the host process.** The parser rejects DTDs and
  bounds nesting depth, but a caller that accepts arbitrarily large request
  bodies still needs its own size limit.
- **Side-channel timing leaks.** Constant-time comparison is used where it
  matters for signature / MAC equality (`subtle`), but rustc / LLVM may still
  emit data-dependent branches. The crate is not engineered against an
  attacker who can run code on the same physical host as the SP.
- **Key compromise.** Once a private key leaks, the crate cannot help —
  rotate the key, re-issue metadata, and revoke trust at the relying party.
  Pluggable `SignatureVerifier` allows HSM- or KMS-backed keys; that's the
  right tool for high-value deployments.
- **Transport security beyond rustls.** The optional `reqwest-client`
  feature uses rustls; bring-your-own `HttpClient` implementations are the
  caller's responsibility. SOAP back-channel TLS pinning, mTLS, and CA
  selection are not in scope for this crate.
- **Identity provider correctness.** If the IdP issues an assertion for the
  wrong subject, no SP-side check can detect it.

## FIPS Mode

The `fips` Cargo feature is **on by default** in this fork. It routes the
crate's cryptographic **operations** and `ReqwestClient` TLS through **AWS-LC**
(the `aws-lc-rs` binding with its `fips` feature / rustls FIPS provider), a
FIPS 140-3 validated cryptographic module, linked statically into the binary.
This does **not** CMVP-certify the `saml` crate itself — only the module is
FIPS-validated. See **`docs/fips/`** and **RFC-009** for the full posture and
evidence pack.

What a `fips` build changes:

- **Routing.** Digests, the certificate SHA-256 fingerprint, all randomness,
  RSA/ECDSA **signing and verification**, the `xmlenc` AES-GCM/CBC and
  RSA-OAEP key-transport paths, the proxy HMAC-SHA-256 / AES-256-GCM context
  codec, and the SP login-tracker and IdP artifact-resolve-transaction
  AES-256-GCM seals all run on AWS-LC (PRs A + B + C2 + C3 + C4 + C5).
- **TLS.** `ReqwestClient::default` / `install_default_crypto_provider()`
  install rustls's aws-lc-rs provider and require `CryptoProvider::fips()`.
- **Policy.** Unpaired RSA-OAEP (label hash ≠ MGF1 hash) is rejected at
  validation time, and sub-2048-bit RSA keys are rejected by the module at
  verify time. `weak-algos` is ignored for the default policy under `fips` —
  `PeerCryptoPolicy::strong_defaults()` never lists SHA-1 or PKCS1-v1.5, so the
  default posture is FIPS-compliant even if `weak-algos` is compiled in. This
  is a *default-policy* guarantee, not a compile-time one: a hand-built
  `PeerCryptoPolicy` that explicitly lists RSA-SHA1 or PKCS1-v1.5 will still
  route those two operations through the pure-Rust `sha1` / `rsa` crates even
  under `fips` + `weak-algos`. The default path never does.
- **Runtime assertion.** `assert_fips_mode()` checks at startup that the
  linked AWS-LC module is actually in FIPS mode and fails closed otherwise,
  catching a build mistake (e.g. `aws-lc-rs` linked without its `fips`
  feature). The same check also runs as a fail-closed backstop on every
  AWS-LC crypto entry point (digest, sign, verify, entropy, AEAD, AES-CBC,
  RSA-OAEP, HMAC, artifact SourceID), so a deployment that never calls it
  still refuses to run non-FIPS crypto.
- **Key lifecycle boundary.** PEM/DER parse and PKCS#8 re-encode still use
  RustCrypto key containers before material is imported into AWS-LC. Crypto
  ops after import are module-backed; parse/encode is documented as outside
  the validated-module boundary (`docs/fips/BOUNDARY.md`).
- **Evidence.** `./scripts/fips-evidence.sh` and the CI `fips-evidence`
  artifact record feature resolution, dependency trees, and runtime
  `try_fips_mode` / rustls provider FIPS checks (`docs/fips/ATTESTATION.md`).

**Effect on the `rsa` advisory.** Routing signing and verification to AWS-LC
removes the pure-Rust `rsa` crate from those two paths in a FIPS build, closing
the RUSTSEC-2023-0071 (Marvin) timing exposure on RSA signing and verification.
With PR C2 landed, the only residual pure-Rust `rsa` *crypto* exposure in a
FIPS build is the legacy RSA-PKCS#1-v1.5 key-transport decryption path, which
is gated behind `weak-algos` and refused by default. RSA-OAEP key transport now
runs on AWS-LC.

## Known Advisories

The dependency audit (`cargo audit` / `cargo deny`) carries one accepted,
documented advisory:

- **RUSTSEC-2023-0071 — `rsa` "Marvin Attack" timing sidechannel.** The
  pure-Rust `rsa` crate's RSA private-key operations are not fully
  constant-time. No fixed release exists: the mitigation is partial and
  unreleased in the in-progress `rsa` 0.10 line (tracked at RustCrypto/RSA#390),
  and even that is described upstream as a "stop the bleeding" fix that does not
  completely close the channel. Pure-Rust RSA has no maintained alternative that
  avoids a C/asm backend, which would defeat this crate's no-C-build-chain
  premise.

  **Exposure here is limited by default.** The practically-exploitable PKCS#1
  v1.5 decryption padding-oracle vector is gated behind the `weak-algos` feature
  and refused by default — only RSA-OAEP key transport is accepted, so the
  classic Bleichenbacher/Marvin oracle is not reachable in a default build.
  SP-side signature *verification* uses no private key and is unaffected. The
  residual is generic non-constant-time modular-exponentiation timing on the
  RSA-OAEP `xmlenc` decryption and RSA signing paths — the same ecosystem-wide
  limitation noted under "Side-channel timing leaks" above, hard to exploit over
  a network.

  Operators who enable `weak-algos` (re-enabling RSA-1.5 key transport) take on
  the full Marvin exposure and should weigh that against their threat model.

  The advisory is recorded in `deny.toml` and the `cargo audit` CI step; it will
  be dropped once `rsa` ships a constant-time stable release.

## HTTP-Redirect SSO Response Binding (metadata-gated)

The Web Browser SSO Profile (OASIS, §4.1.3 *Profile Description*, step 5)
states:

> Either the HTTP POST, or HTTP Artifact binding can be used to transfer the
> message to the service provider through the user agent. … **The HTTP
> Redirect binding MUST NOT be used, as the response will typically exceed
> the URL length permitted by most user agents.**

This crate therefore does **not** accept HTTP-Redirect-bound `<Response>`
messages by default. Acceptance is a documented, opt-in exception for
interoperability with IdPs that do send Redirect responses (the SAML 2.0
Bindings spec, §3.4 and §3.4.4.1, fully defines the binding, including its
detached query-string signature). The opt-in is expressed through metadata: an
SP accepts a Redirect-bound response **only if its own metadata advertises an
ACS endpoint with the HTTP-Redirect binding**. An SP that has not advertised a
Redirect ACS rejects such a response with `Error::RedirectResponseNotAdvertised`
(fail closed) — the Profile's default, with no configuration change.

When accepted, the binding is held to three controls:

- **Mandatory detached signature.** A Redirect-bound response must carry a
  detached query-string signature (Bindings §3.4.4.1). Its absence is a hard
  error (`Error::SignatureMissing`), independent of the SP's `want_signed`
  policy — over an unauthenticated GET, the query string is the only integrity
  anchor available.
- **Signed-query → XML binding.** The `SAMLResponse` and `RelayState` values
  in the parsed body must byte-match the values covered by the detached
  signature (`ensure_signed_query_matches_response`). A response whose body
  differs from its signed query is rejected (`Error::SignatureVerification`),
  closing the "signed one thing, sent another" vector.
- **Existing signature policy still applies.** The detached query signature is
  *additive*. A Redirect response must still satisfy the SP's `want_signed`
  policy with an XML-level (envelope) signature on the Response root and/or
  Assertion, exactly as a POST response would. The two signatures are checked
  independently and both must pass.

**Audit posture.** This is a deliberate, scoped deviation from the Profile's
MUST NOT, gated behind explicit metadata (a Redirect ACS) and held to the
controls above. The Profile's stated rationale is a practical URL-length
limit, not a security property; the mandatory detached signature plus the
signed-query→XML binding provide the integrity the Profile assumes is absent.
This IdP does not *issue* Redirect responses (the outbound dispatch returns
`Error::UnsupportedByPeer`), so the deviation is inbound-only and never widens
what this crate sends on the wire.

## Disclosure Timeline

Standard timeline is **90 days** from receipt of the report to public
disclosure, regardless of fix availability. We aim to publish a fixed
release well within that window.

If you need a faster disclosure (for example, evidence of active
exploitation), say so in the initial report — we will accelerate. If you
need a slower disclosure for coordinated multi-party fixes, say so as well
and we will negotiate a date.

After a fixed release is published, the CHANGELOG entry will reference the
issue (with a CVE identifier if assigned) and credit the reporter unless
they prefer to remain anonymous.
