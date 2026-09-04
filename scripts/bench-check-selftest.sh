#!/usr/bin/env bash
#
# Self-test for scripts/bench-check.sh. Feeds it canned "go test -bench"
# output and canned baselines and asserts the exit codes, so the regression
# gate is not the one untested thing in the build.
#
# No Go is run: BENCH_INPUT stands in for the benchmark output, which is what
# makes the pass, regression, missing-baseline and malformed cases
# reproducible on any machine.
#
# Usage: scripts/bench-check-selftest.sh

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
gate="$script_dir/bench-check.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

failures=0

# A realistic two-benchmark run at -count=3. The fastest repeat of the 1 MiB
# push is 1000000 ns/op, so "best of N" must compare that and not the mean
# (1100000) or the worst (1200000).
cat >"$tmp/bench.out" <<'EOF'
goos: linux
goarch: amd64
pkg: github.com/steveokay/trove/internal/registry
cpu: AMD EPYC 7763 64-Core Processor
BenchmarkMonolithicBlobPush1MiB-4   	      20	   1200000 ns/op	 873.81 MB/s	 2142344 B/op	      69 allocs/op
BenchmarkMonolithicBlobPush1MiB-4   	      20	   1000000 ns/op	1048.58 MB/s	 2142344 B/op	      69 allocs/op
BenchmarkMonolithicBlobPush1MiB-4   	      20	   1100000 ns/op	 953.25 MB/s	 2142344 B/op	      69 allocs/op
BenchmarkManifestPut-4              	      20	    100000 ns/op	   67632 B/op	     255 allocs/op
BenchmarkManifestPut-4              	      20	    104000 ns/op	   67632 B/op	     255 allocs/op
BenchmarkManifestPut-4              	      20	    102000 ns/op	   67632 B/op	     255 allocs/op
PASS
ok  	github.com/steveokay/trove/internal/registry	9.001s
EOF

# The benchmark output the gate reads. Reassigned by the malformed-input cases.
input="$tmp/bench.out"

# assert <name> <expected-exit> <baseline-file> [tolerance]
assert() {
	local name="$1" want="$2" baseline="$3" tolerance="${4:-}"
	local got=0
	(
		export BENCH_INPUT="$input"
		if [[ -n "$tolerance" ]]; then
			export BENCH_TOLERANCE="$tolerance"
		fi
		bash "$gate" "$baseline" "$tmp/candidate.txt"
	) >"$tmp/last.log" 2>&1 || got=$?
	if [[ "$got" -eq "$want" ]]; then
		echo "ok   - $name"
	else
		echo "FAIL - $name: exit $got, want $want"
		sed 's/^/       | /' "$tmp/last.log"
		failures=$((failures + 1))
	fi
}

# contains <name> <needle> -- inspects the output of the assertion just run.
contains() {
	local name="$1" needle="$2"
	if grep -qF -- "$needle" "$tmp/last.log"; then
		echo "ok   - $name"
	else
		echo "FAIL - $name: output lacks '$needle'"
		sed 's/^/       | /' "$tmp/last.log"
		failures=$((failures + 1))
	fi
}

# --- pass -------------------------------------------------------------------
printf 'BenchmarkMonolithicBlobPush1MiB 1000000\nBenchmarkManifestPut 100000\n' >"$tmp/exact.txt"
assert "measurements equal to the baseline pass" 0 "$tmp/exact.txt"
contains "the pass prints a comparison table" "measured ns/op"
contains "the pass names the tolerance" "within 20%"

printf 'BenchmarkMonolithicBlobPush1MiB 2000000\nBenchmarkManifestPut 200000\n' >"$tmp/generous.txt"
assert "a run faster than the baseline passes" 0 "$tmp/generous.txt"

# 1000000 against a 900000 baseline is 11.1% slower: inside the tolerance.
printf 'BenchmarkMonolithicBlobPush1MiB 900000\nBenchmarkManifestPut 100000\n' >"$tmp/within.txt"
assert "slower but within tolerance passes" 0 "$tmp/within.txt"

# Best-of-N proved by the boundary: a baseline of 1000000 is exactly the
# fastest repeat. Against the mean or the worst this run would be a
# regression, so passing here can only mean the minimum was taken.
printf 'BenchmarkMonolithicBlobPush1MiB 1000000\n' >"$tmp/best-only.txt"
assert "the fastest repeat is the one compared" 0 "$tmp/best-only.txt"

# Exactly at the tolerance is not a regression: the gate fires above it.
printf 'BenchmarkEdge-4   \t  20\t   1200000 ns/op\t 2142344 B/op\n' >"$tmp/edge.out"
printf 'BenchmarkEdge 1000000\n' >"$tmp/edge.txt"
input="$tmp/edge.out"
assert "exactly 20 percent slower is not yet a regression" 0 "$tmp/edge.txt"
assert "a hair over the tolerance is a regression" 1 "$tmp/edge.txt" 19.9
input="$tmp/bench.out"

# --- regression -------------------------------------------------------------
printf 'BenchmarkMonolithicBlobPush1MiB 800000\nBenchmarkManifestPut 100000\n' >"$tmp/regressed.txt"
assert "more than 20 percent slower fails" 1 "$tmp/regressed.txt"
contains "the failure marks the regressed benchmark" "REGRESSION"
contains "the failure prints the baseline number" "800000"
contains "the failure prints the measured number" "1000000"
contains "the failure names the benchmark" "BenchmarkMonolithicBlobPush1MiB"

# A regression anywhere fails, even with every other benchmark healthy.
printf 'BenchmarkMonolithicBlobPush1MiB 1000000\nBenchmarkManifestPut 10000\n' >"$tmp/one-bad.txt"
assert "one regressed benchmark fails the run" 1 "$tmp/one-bad.txt"

# The tolerance is configurable in both directions.
assert "a tighter tolerance is honoured" 1 "$tmp/within.txt" 5
assert "a looser tolerance is honoured" 0 "$tmp/regressed.txt" 50

# --- missing baseline: record, never fail -----------------------------------
assert "an absent baseline records instead of failing" 0 "$tmp/does-not-exist.txt"
contains "the absent baseline is announced" "no baseline at"
contains "the absent baseline prints the numbers" "BenchmarkMonolithicBlobPush1MiB 1000000"
contains "the absent baseline names the candidate file" "$tmp/candidate.txt"
if [[ -s "$tmp/candidate.txt" ]]; then
	echo "ok   - the candidate file was written"
else
	echo "FAIL - the candidate file was not written"
	failures=$((failures + 1))
fi

# What it records is a baseline it then accepts: the candidate round-trips
# rather than being a differently shaped report.
cp "$tmp/candidate.txt" "$tmp/round-trip.txt"
assert "the recorded candidate is a usable baseline" 0 "$tmp/round-trip.txt"

# A baseline covering only some of the benchmarks is not a failure either,
# and the ones it does cover are still enforced.
printf 'BenchmarkManifestPut 100000\n' >"$tmp/partial.txt"
assert "a baseline missing an entry records instead of failing" 0 "$tmp/partial.txt"
contains "the unbaselined benchmark is listed" "BenchmarkMonolithicBlobPush1MiB"
contains "the unbaselined benchmark is marked new" "  new"
contains "the partial baseline still asks for a commit" "written to"

printf 'BenchmarkManifestPut 10000\n' >"$tmp/partial-bad.txt"
assert "a partial baseline still catches a regression" 1 "$tmp/partial-bad.txt"

# A baseline entry with no measurement is reported, not fatal: a benchmark
# may have been renamed, and that must not read as a regression.
printf 'BenchmarkMonolithicBlobPush1MiB 1000000\nBenchmarkManifestPut 100000\nBenchmarkGone 5\n' >"$tmp/stale.txt"
assert "a stale baseline entry does not fail the run" 0 "$tmp/stale.txt"
contains "the stale entry is reported" "not measured"

# Comments and blank lines are baseline syntax, not junk -- the candidate the
# script writes carries a comment header.
printf '# a comment\n\n   \nBenchmarkMonolithicBlobPush1MiB 1000000  # trailing\nBenchmarkManifestPut 100000\n' \
	>"$tmp/commented.txt"
assert "comments and blank lines are accepted" 0 "$tmp/commented.txt"

# --- malformed input --------------------------------------------------------
printf 'BenchmarkMonolithicBlobPush1MiB 1000000\nthis is not a baseline line\n' >"$tmp/junk.txt"
assert "a malformed baseline line is an error" 2 "$tmp/junk.txt"
contains "the malformed line is named by number" "malformed baseline line 2"

printf 'BenchmarkMonolithicBlobPush1MiB notanumber\n' >"$tmp/nonnumeric.txt"
assert "a non-numeric baseline value is an error" 2 "$tmp/nonnumeric.txt"

printf 'NotABenchmark 1000\n' >"$tmp/notabench.txt"
assert "a baseline naming a non-benchmark is an error" 2 "$tmp/notabench.txt"

printf 'BenchmarkMonolithicBlobPush1MiB 0\n' >"$tmp/zero.txt"
assert "a zero baseline is an error, not a division by zero" 2 "$tmp/zero.txt"

# Output with no benchmark results is an error, never a silent pass: a build
# that stopped running the benchmarks must not look green.
printf 'goos: linux\nPASS\nok  \tpkg\t0.1s\n' >"$tmp/nobench.out"
input="$tmp/nobench.out"
assert "benchmark output with no results is an error" 2 "$tmp/exact.txt"

printf 'BenchmarkBroken-4 \t 20 \t  wat ns/op\n' >"$tmp/badns.out"
input="$tmp/badns.out"
assert "an unparseable ns/op is an error" 2 "$tmp/exact.txt"

input="$tmp/no-such-file.out"
assert "an absent input file is an error" 2 "$tmp/exact.txt"
input="$tmp/bench.out"

assert "a non-numeric tolerance is an error" 2 "$tmp/exact.txt" lots

if [[ "$failures" -ne 0 ]]; then
	echo "$failures assertion(s) failed" >&2
	exit 1
fi
echo "all bench-gate assertions passed"
