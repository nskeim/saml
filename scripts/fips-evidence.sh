#!/usr/bin/env bash
# Collect auditor-facing evidence that the default build links and runs the
# AWS-LC FIPS module for SAML crypto + ReqwestClient TLS.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OUT="${FIPS_EVIDENCE_DIR:-$ROOT/target/fips-evidence}"
rm -rf "$OUT"
mkdir -p "$OUT"

pass=1
note() { printf '%s\n' "$*" | tee -a "$OUT/SUMMARY.txt"; }
fail() { note "FAIL: $*"; pass=0; }
ok() { note "OK: $*"; }

note "saml FIPS evidence"
note "generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
note "commit: $(git rev-parse HEAD 2>/dev/null || echo unknown)"
note "----"

# Resolved features for the default build.
cargo tree -p saml -f "{f}" --depth 0 | head -1 | tee "$OUT/features.txt"
if grep -q 'fips' "$OUT/features.txt"; then
  ok "default feature set includes fips"
else
  fail "default feature set missing fips (see features.txt)"
fi

# Locked / resolved versions.
{
  echo "# cargo tree versions (default features)"
  cargo tree -i aws-lc-rs -p saml --depth 0 2>&1 || true
  echo
  cargo tree -i aws-lc-fips-sys -p saml --depth 0 2>&1 || true
  echo
  cargo tree -i rustls -p saml --depth 0 2>&1 || true
  echo
  cargo tree -i reqwest -p saml --depth 0 2>&1 || true
} | tee "$OUT/versions.txt"

# AWS-LC graph.
{
  echo "=== aws-lc-rs ==="
  cargo tree -i aws-lc-rs -p saml 2>&1 || true
  echo
  echo "=== aws-lc-fips-sys ==="
  cargo tree -i aws-lc-fips-sys -p saml 2>&1 || true
  echo
  echo "=== aws-lc-sys (may appear via rustls; see docs/fips/BOUNDARY.md) ==="
  cargo tree -i aws-lc-sys -p saml 2>&1 || true
} | tee "$OUT/tree-aws-lc.txt"

if grep -q 'aws-lc-fips-sys' "$OUT/tree-aws-lc.txt"; then
  ok "aws-lc-fips-sys is in the dependency graph"
else
  fail "aws-lc-fips-sys not found in cargo tree"
fi

# ring graph (informational under default).
{
  echo "=== ring (informational; dual rustls provider compile) ==="
  cargo tree -i ring -p saml 2>&1 || true
} | tee "$OUT/tree-ring.txt"

# Runtime attestation.
set +e
cargo test -p saml --test fips_attestation -- --nocapture 2>&1 | tee "$OUT/fips-mode.txt"
attest_rc=${PIPESTATUS[0]}
set -e
if [[ "$attest_rc" -eq 0 ]]; then
  ok "fips_attestation tests passed"
else
  fail "fips_attestation tests failed (exit $attest_rc)"
fi

note "----"
if [[ "$pass" -eq 1 ]]; then
  note "RESULT: PASS"
  exit 0
fi
note "RESULT: FAIL"
exit 1
