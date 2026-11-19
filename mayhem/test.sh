#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
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

# massdns' own tests/ query 8.8.8.8, which the air-gapped grader cannot reach. This runs the same
# kind of end-to-end check offline: the upstream-built bin/massdns resolves mayhem/tests/names.txt
# against a canned resolver on 127.0.0.1 (mayhem/tests/fake_resolver.py), once per output format,
# and the output — normalised for the fields that vary per run (timestamps, query ids, resolver
# port) and sorted, since replies arrive in any order — must equal the golden file.
BIN="$SRC/bin/massdns"
T="$SRC/mayhem/tests"
if [ ! -x "$BIN" ]; then
  echo "missing $BIN — mayhem/build.sh must build it" >&2
  emit_ctrf massdns-e2e 0 1 0
  exit 1
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/massdns-test.XXXXXX")"
python3 -I "$T/fake_resolver.py" "$work/port" &
resolver_pid=$!
trap 'kill "$resolver_pid" 2>/dev/null; rm -rf "$work"' EXIT
for _ in $(seq 100); do [ -s "$work/port" ] && break; sleep 0.1; done
if [ ! -s "$work/port" ]; then
  echo "fake resolver did not start" >&2
  emit_ctrf massdns-e2e 0 1 0
  exit 1
fi
echo "127.0.0.1:$(cat "$work/port")" > "$work/resolvers.txt"

normalize() {
  sed -E -e 's/"rx_ts":[0-9]+/"rx_ts":0/' \
         -e 's/127\.0\.0\.1:[0-9]+/127.0.0.1:PORT/g' \
         -e 's/^;; Unix time: [0-9]+$/;; Unix time: 0/' \
         -e 's/, id: [0-9]+$/, id: 0/' | LC_ALL=C sort
}

passed=0 failed=0
for fmt in S J L F; do
  if timeout 60 "$BIN" -c 3 --quiet -r "$work/resolvers.txt" -o "$fmt" -w "$work/out.$fmt" "$T/names.txt" \
     && normalize < "$work/out.$fmt" | diff -u "$T/expected/out.$fmt" - ; then
    echo "PASS massdns -o $fmt"; passed=$((passed + 1))
  else
    echo "FAIL massdns -o $fmt"; failed=$((failed + 1))
  fi
done

emit_ctrf massdns-e2e "$passed" "$failed" 0
