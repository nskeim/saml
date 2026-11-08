# CMVP / validated module references

## Module in use

| Component | Role |
| --- | --- |
| **AWS-LC** (FIPS build) | FIPS 140-3 validated cryptographic module |
| `aws-lc-fips-sys` | Rust sys crate that builds/links the FIPS module from source |
| `aws-lc-rs` (feature `fips`) | Safe Rust API used by this crate and by rustls's FIPS provider |

Pinned versions for a given checkout are recorded in `Cargo.lock` and copied
into evidence output by `./scripts/fips-evidence.sh` (`versions.txt`).

## How to verify validation status

1. Read the locked `aws-lc-fips-sys` / `aws-lc-rs` versions from evidence or:
   ```sh
   cargo tree -i aws-lc-fips-sys -p saml
   cargo tree -i aws-lc-rs -p saml
   ```
2. Consult the NIST CMVP validated-modules search for **AWS-LC** (active
   certificates):
   - <https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search>
3. Cross-check the module version / implementation guidance published by the
   AWS LibCrypto project for the FIPS build corresponding to that
   `aws-lc-fips-sys` release:
   - <https://github.com/aws/aws-lc>
   - <https://github.com/aws/aws-lc-rs>

Certificate numbers and module versions change over time as AWS-LC revalidates.
**Do not hard-code a stale certificate ID in compliance packages** — always
pair the lockfile versions from this repository revision with the live CMVP
listing.

## What CMVP covers vs what this crate does

- CMVP validates the **cryptographic module** (AWS-LC), not the SAML protocol
  engine.
- This crate's evidence shows we **link and invoke** that module in FIPS mode
  for the operations in [CRYPTO_INVENTORY.md](CRYPTO_INVENTORY.md).
- A complete system authorization still needs platform, key management, and
  operational controls outside this repository.
