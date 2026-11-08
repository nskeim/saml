# Attestation / evidence

## Produce evidence locally

Requirements: Rust toolchain matching `rust-version`, C compiler, `cmake`, `go`.

```sh
./scripts/fips-evidence.sh
```

Outputs under `target/fips-evidence/`:

| File | Meaning |
| --- | --- |
| `features.txt` | Resolved `saml` Cargo features for the default build |
| `versions.txt` | Locked versions of `aws-lc-rs`, `aws-lc-fips-sys`, `rustls`, `reqwest` |
| `tree-aws-lc.txt` | `cargo tree` for `aws-lc-rs` / `aws-lc-fips-sys` / `aws-lc-sys` |
| `tree-ring.txt` | Whether `ring` appears (expected under default: rustls dual provider; TLS runtime uses AWS-LC) |
| `fips-mode.txt` | Output of `cargo test --test fips_attestation` |
| `SUMMARY.txt` | Pass/fail summary suitable for an evidence binder |

The script **exits non-zero** if FIPS mode attestation fails.

## CI

The `fips-evidence` GitHub Actions job runs the same script on default features
and uploads `target/fips-evidence/` as the `fips-evidence` workflow artifact.

## Interpreting results

**Pass criteria**

1. `features.txt` lists `fips` (and typically `reqwest-client`).
2. `tree-aws-lc.txt` shows `aws-lc-fips-sys` reachable from `saml`.
3. `fips-mode.txt` / attestation tests show:
   - `assert_fips_mode()` → `Ok`
   - `aws_lc_rs::try_fips_mode()` → `Ok`
   - rustls default provider `fips()` → `true` after `install_default_crypto_provider()`
4. `SUMMARY.txt` ends with `RESULT: PASS`.

**Expected non-failures**

- `ring` may appear in `tree-ring.txt` because `reqwest-client` enables
  `rustls/ring` for the non-FIPS opt-out. Runtime provider under default is
  still AWS-LC FIPS (attestation checks `CryptoProvider::fips()`).
- `aws-lc-sys` may appear alongside `aws-lc-fips-sys` via rustls feature
  unification ([BOUNDARY.md](BOUNDARY.md)). FIPS mode must still pass.

## Manual spot checks

```sh
# Module mode
cargo test -p saml --test fips_attestation -- --nocapture

# Opt-out still builds (non-FIPS retained)
cargo test -p saml --no-default-features \
  --features reqwest-client,rsa-sha,ecdsa-sha,xmlenc,slo,metadata-emit,xsd-validate
```
