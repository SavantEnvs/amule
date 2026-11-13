#!/usr/bin/env bash
#
# mayhem/test.sh — RUN aMule's muleunit suites plus a known-answer probe (both built by mayhem/build.sh).
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

B="$SRC/build/tests"
passed=0
failed=0

# 1) aMule's own muleunit suites. Each prints `Running test-collection "X" with N test-cases:` and a
#    `Failure ...` block per failed assertion; the process exits non-zero if any case failed.
for t in CTagTest CUInt128Test FileDataIOTest FormatTest NetworkFunctionsTest PathTest PhpArrayTest \
         RangeMapTest StringFunctionsTest TextFileTest; do
  exe="$B/unittests/tests/$t"
  if [ ! -x "$exe" ]; then
    echo "missing test runner $exe (mayhem/build.sh should have built it)" >&2
    failed=$((failed + 1)); continue
  fi
  out=$("$exe" 2>&1); rc=$?
  printf '%s\n' "$out"
  n=$(printf '%s\n' "$out" | sed -n 's/^Running test-collection ".*" with \([0-9][0-9]*\) test-cases:.*/\1/p' | awk '{s+=$1} END {print s+0}')
  f=$(printf '%s\n' "$out" | grep -c 'Failure' || true)
  if [ "$rc" -ne 0 ] && [ "$f" -eq 0 ]; then f=1; fi
  if [ "$n" -eq 0 ]; then
    echo "$t ran no test cases" >&2
    n=1; f=1
  fi
  [ "$f" -gt "$n" ] && f=$n
  failed=$((failed + f))
  passed=$((passed + n - f))
done

# 2) Known-answer probe: real values out of the eD2k link, magnet, RLE, tag-stream and EC parsers.
kat="$B/kat"
if [ ! -x "$kat" ]; then
  echo "missing known-answer probe $kat" >&2
  failed=$((failed + 1))
else
  kat_out=$("$kat" 2>&1)
  expected=$(cat <<'EXP'
file.kind=2
file.name=Some File.bin
file.size=123456789
file.hash=0123456789ABCDEF0123456789ABCDEF
file.link=ed2k://|file|Some File.bin|123456789|0123456789ABCDEF0123456789ABCDEF|/
server.kind=1
server.port=4661
server.link=ed2k://|server|1.2.3.4|4661|/
bad.rejected=1
magnet.convertible=1
magnet.ed2k=ed2k://|file|Test.bin|1234|0123456789ABCDEF0123456789ABCDEF|/
magnet.a=2
magnet.link=magnet:?a=1&b=2&a=3
rle.size=6
rle.data=AAABCC
rle.diff=0,3,2,5
tag1.name=1 int=0xdeadbeef
tag2.name=2
tag2.str=hello
tag.truncated_rejected=1
ec.wire_bytes=39
ec.packets=1
ec.opcode=0x0a
ec.string=amule-kat
ec.number=0x1020304
ec.oversize_packets=0
EXP
)
  while IFS= read -r line; do
    if printf '%s\n' "$kat_out" | grep -Fxq -- "$line"; then
      passed=$((passed + 1))
    else
      echo "KAT mismatch: expected line '$line'" >&2
      failed=$((failed + 1))
    fi
  done <<< "$expected"
fi

emit_ctrf "aMule muleunit + known-answer probe" "$passed" "$failed" 0
