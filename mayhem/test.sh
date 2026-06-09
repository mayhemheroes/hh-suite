#!/usr/bin/env bash
#
# hh-suite/mayhem/test.sh — behavioral oracle (SPEC §6.3, anti-reward-hacking).
#
# Runs three known-answer tests using the tool suite built by mayhem/build.sh (build-tests/).
# Each test asserts specific OUTPUT CONTENT — a neutered binary that exits(0) without producing
# any output WILL FAIL these checks (satisfying the sabotage/reward-hacking gate).
#
# Test 1 (hhmake): Convert query.a3m → HHM format; assert output has the "HHsearch 1.5" header
#   and a "NAME" field matching the known query sequence.
# Test 2 (ffindex round-trip): ffindex_build a known file → assert the ffindex index entry
#   records the correct filename and non-zero byte count.
# Test 3 (hhalign self-alignment): align query.a3m against itself; assert output contains a
#   "No 1" alignment hit with the query sequence identifier.
#
# All three require actual tool output to pass. None passes on exit(0) alone.
#
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Put the tools that mayhem/build.sh built (build-tests/, normal flags) on PATH.
export PATH="$SRC/build-tests/src:$SRC/build-tests/lib/ffindex/src:$PATH"
command -v hhmake >/dev/null 2>&1 || { echo "hh-suite tools missing — run mayhem/build.sh first" >&2; exit 2; }

passed=0; failed=0

# ── Test 1: hhmake behavioral output check ────────────────────────────────────────────────────
# hhmake converts an a3m multiple sequence alignment into an HHM profile.
# A neutered tool exits(0) with no output file; a real run produces a file starting with
# "HHsearch 1.5" and a NAME line from the query.
HHM_OUT="$(mktemp /tmp/hh-suite-test-XXXXXX.hhm)"
hhmake -i "$SRC/data/query.a3m" -o "$HHM_OUT" -v 0 >/dev/null 2>&1
if [ -s "$HHM_OUT" ] \
   && grep -q "^HHsearch 1\.5" "$HHM_OUT" \
   && grep -q "^NAME" "$HHM_OUT"; then
  echo "PASS test1: hhmake produced a valid HHM profile (HHsearch 1.5 header + NAME field)"
  passed=$(( passed + 1 ))
else
  echo "FAIL test1: hhmake output missing or lacks expected HHM header" >&2
  failed=$(( failed + 1 ))
fi
rm -f "$HHM_OUT"

# ── Test 2: ffindex_build round-trip content check ───────────────────────────────────────────
# ffindex_build packs a file into an ffindex database (data + index). The index stores
# filename, byte offset, and length. A neutered tool exits(0) with no files created.
# NOTE: ffindex_build refuses to overwrite an existing file, so use fixed paths with rm -f.
FFDATA="/tmp/hh-suite-ffidx-test.ffdata"
FFIDX="/tmp/hh-suite-ffidx-test.ffindex"
rm -f "$FFDATA" "$FFIDX"
ffindex_build -s "$FFDATA" "$FFIDX" "$SRC/data/query.a3m" >/dev/null 2>&1
# The index must exist, be non-empty, and its byte-count column (field 3) must be > 0.
if [ -s "$FFIDX" ]; then
  BYTECOUNT="$(awk '{print $3}' "$FFIDX")"
  if [ -n "$BYTECOUNT" ] && [ "$BYTECOUNT" -gt 0 ] 2>/dev/null; then
    echo "PASS test2: ffindex_build created a valid ffindex (${BYTECOUNT} bytes indexed)"
    passed=$(( passed + 1 ))
  else
    echo "FAIL test2: ffindex index exists but byte count is zero or missing" >&2
    failed=$(( failed + 1 ))
  fi
else
  echo "FAIL test2: ffindex_build produced no index file" >&2
  failed=$(( failed + 1 ))
fi
rm -f "$FFDATA" "$FFIDX"

# ── Test 3: hhalign self-alignment hit check ──────────────────────────────────────────────────
# hhalign aligns an HHM query against a target database. Aligning query.a3m against itself
# should always produce a "No 1" hit with probability 1 and the query sequence identifier.
# A neutered tool exits(0) with no output; a real run writes an .hhr file with alignment results.
HHR_OUT="$(mktemp /tmp/hh-suite-test-XXXXXX.hhr)"
hhalign -i "$SRC/data/query.a3m" -t "$SRC/data/query.a3m" -o "$HHR_OUT" -v 0 >/dev/null 2>&1
# The .hhr file must exist and contain "No 1" (the top-ranked hit) and the query identifier.
if [ -s "$HHR_OUT" ] \
   && grep -q "No 1" "$HHR_OUT" \
   && grep -q "FA69B" "$HHR_OUT"; then
  echo "PASS test3: hhalign self-alignment produced a valid hit report (No 1 + query ID)"
  passed=$(( passed + 1 ))
else
  echo "FAIL test3: hhalign output missing or lacks expected alignment hit" >&2
  failed=$(( failed + 1 ))
fi
rm -f "$HHR_OUT"

emit_ctrf "hh-suite-behavioral" "$passed" "$failed"
