#!/usr/bin/env bash
#
# Push-latency regression gate (R-012).
#
# Push latency is a hard SLO (CLAUDE.md section 6). This runs the registry
# push benchmarks, reduces each to one ns/op number, and compares that against
# a committed baseline. A benchmark slower than its baseline by more than the
# tolerance fails the build with the comparison printed.
#
# Aggregation: -count runs per benchmark, and the BEST (minimum) ns/op wins.
# Benchmark noise is one-sided -- a co-tenant on the runner can only make a run
# slower, never faster than the hardware allows -- so the minimum is the least
# contaminated estimate of the machine's true speed. A median still carries
# whatever contention was present for half the runs, which on a shared CI
# runner is most of them.
#
# -benchtime is pinned so a run is reproducible, and pinned to a duration
# rather than to a fixed iteration count. These benchmarks span four orders of
# magnitude -- a 100 MiB push is ~65 ms, a manifest PUT ~10 us -- and any one
# iteration count that keeps the big one tolerable gives the small one so few
# samples that it measures scheduler noise. A duration lets each benchmark
# choose a count matched to its own cost.
#
# A baseline is only comparable to a measurement taken on the same hardware,
# and a hosted CI runner is not one machine. This gate was written believing it
# was -- "capture the baseline on the runner that enforces it" -- and that
# premise failed on 2026-09-07: one commit that touched no production code came
# back 38% slower on BenchmarkMonolithicBlobPush100MiB, with an identical
# allocation profile, because the job landed on an Intel Xeon 8370C instead of
# the AMD EPYC the baseline was taken on. Across four runs the same benchmark
# measured 79 ms, 96 ms, 103 ms and 134 ms purely by machine, while the 1 MiB
# variant barely moved: the large push is DRAM-bandwidth bound and the small
# one fits in cache, so the machines differ where it hurts.
#
# The fix is not a looser tolerance -- that would blind the gate to a real 30%
# regression -- but comparing like with like: CI measures the previous commit
# and this one in the same job, on the same machine, and passes the first as
# the baseline for the second. Nothing here needed to change for that; the
# recording mode below already emits a baseline file. What changed is what CI
# feeds it.
#
# The committed scripts/bench-baseline.txt survives as long-run drift context,
# read in advisory mode so a machine change reports rather than fails.
#
# When the baseline file is absent, or has no entry for a benchmark, that is
# NOT a failure: the measured numbers are printed in baseline format and
# written to the candidate file, which is both how a baseline is minted and how
# the same-machine comparison gets its first half.
#
# Usage: scripts/bench-check.sh [baseline] [candidate]
#
# Environment:
#   BENCH_BASELINE   baseline path       (default scripts/bench-baseline.txt)
#   BENCH_CANDIDATE  candidate path      (default bench-candidate.txt)
#   BENCH_TOLERANCE  percent slower allowed before failing (default 20)
#   BENCH_ADVISORY   any non-empty value reports without failing the build
#   BENCH_PKG        package to benchmark (default ./internal/registry/)
#   BENCH_TIME       -benchtime value    (default 1s)
#   BENCH_COUNT      -count value        (default 3)
#   BENCH_INPUT      read benchmark output from this file instead of running
#                    "go test" -- how the self-test feeds it canned results
#   BENCH_RAW        also save the raw benchmark output here, so a second
#                    comparison can read it back through BENCH_INPUT rather
#                    than paying for the benchmarks twice
#
# Exit codes: 0 pass, baseline recorded, or advisory; 1 regression; 2 bad input.

set -euo pipefail

BASELINE="${1:-${BENCH_BASELINE:-scripts/bench-baseline.txt}}"
CANDIDATE="${2:-${BENCH_CANDIDATE:-bench-candidate.txt}}"
TOLERANCE="${BENCH_TOLERANCE:-20}"
ADVISORY="${BENCH_ADVISORY:-}"
PKG="${BENCH_PKG:-./internal/registry/}"
BENCHTIME="${BENCH_TIME:-1s}"
COUNT="${BENCH_COUNT:-3}"
INPUT="${BENCH_INPUT:-}"
RAW_OUT="${BENCH_RAW:-}"

if ! [[ "$TOLERANCE" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
	echo "bench: tolerance must be a non-negative number, got: $TOLERANCE" >&2
	exit 2
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

raw="$tmp/bench.out"
if [[ -n "$INPUT" ]]; then
	if [[ ! -f "$INPUT" ]]; then
		echo "bench: input not found: $INPUT" >&2
		exit 2
	fi
	cp "$INPUT" "$raw"
else
	echo "bench: go test -bench=. -benchtime=$BENCHTIME -count=$COUNT $PKG"
	go test -run '^$' -bench=. -benchmem -benchtime="$BENCHTIME" -count="$COUNT" "$PKG" | tee "$raw"
	echo
fi

# Keeping the raw output lets a second comparison read the same measurement
# back instead of running the benchmarks again. Two comparisons of one run say
# more than two runs compared to different things, and cost a third of the time.
if [[ -n "$RAW_OUT" ]]; then
	cp "$raw" "$RAW_OUT"
fi

# Reduce the raw output to "<name> <best ns/op>", one line per benchmark, in
# the order the benchmarks first appeared. The ns/op column is located by its
# unit label rather than by position, because -benchmem and b.SetBytes both
# add columns.
measured="$tmp/measured.txt"
if ! awk '
	/^Benchmark/ {
		name = $1
		sub(/-[0-9]+$/, "", name)
		ns = ""
		for (i = 2; i <= NF; i++) {
			if ($i == "ns/op") ns = $(i - 1)
		}
		if (ns == "") next
		if (ns !~ /^[0-9]+(\.[0-9]+)?$/) {
			printf "bench: unparseable ns/op for %s: %s\n", name, ns > "/dev/stderr"
			bad = 1
			exit 2
		}
		if (!(name in best) || ns + 0 < best[name]) best[name] = ns + 0
		if (!(name in seen)) { seen[name] = 1; order[++n] = name }
	}
	END {
		if (bad) exit 2
		if (n == 0) {
			print "bench: no benchmark results in the output" > "/dev/stderr"
			exit 2
		}
		for (i = 1; i <= n; i++) printf "%s %d\n", order[i], best[order[i]]
	}
' "$raw" >"$measured"; then
	exit 2
fi

baseline_input="$BASELINE"
if [[ ! -f "$baseline_input" ]]; then
	echo "bench: no baseline at $BASELINE -- recording instead of enforcing"
	baseline_input=/dev/null
fi

status=0
awk -v tol="$TOLERANCE" -v basefile="$baseline_input" '
	# First file: the committed baseline. Matched by FILENAME rather than the
	# usual FNR == NR, which would misread the measurements as baseline lines
	# when the baseline is absent and /dev/null yields no records at all.
	#
	# A corrupt baseline is loud, never quietly ignored -- silently skipping a
	# line would disable the gate for whatever benchmark that line named.
	FILENAME == basefile {
		line = $0
		sub(/#.*/, "", line)
		gsub(/^[ \t]+|[ \t]+$/, "", line)
		if (line == "") next
		fields = split(line, f, /[ \t]+/)
		if (fields != 2 || f[1] !~ /^Benchmark[A-Za-z0-9_]+$/ || f[2] !~ /^[0-9]+(\.[0-9]+)?$/) {
			printf "bench: malformed baseline line %d: %s\n", FNR, $0 > "/dev/stderr"
			bad = 1
			exit 2
		}
		if (f[2] + 0 <= 0) {
			printf "bench: baseline line %d is not a positive ns/op: %s\n", FNR, $0 > "/dev/stderr"
			bad = 1
			exit 2
		}
		base[f[1]] = f[2] + 0
		next
	}

	# Second file: the measured numbers, already reduced.
	{ order[++n] = $1; got[$1] = $2 + 0 }

	END {
		if (bad) exit 2

		printf "%-36s %14s %14s %10s  %s\n", "benchmark", "baseline ns/op", "measured ns/op", "delta", "verdict"
		printf "%-36s %14s %14s %10s  %s\n", "---------", "--------------", "--------------", "-----", "-------"

		for (i = 1; i <= n; i++) {
			name = order[i]
			m = got[name]
			if (!(name in base)) {
				printf "%-36s %14s %14d %10s  %s\n", name, "-", m, "-", "new"
				fresh = 1
				continue
			}
			b = base[name]
			delta = (m - b) / b * 100
			verdict = "ok"
			if (delta > tol + 0) {
				verdict = "REGRESSION"
				failed = 1
			}
			printf "%-36s %14d %14d %+9.1f%%  %s\n", name, b, m, delta, verdict
			seen[name] = 1
		}

		for (name in base) {
			if (!(name in seen) && !(name in got)) {
				printf "%-36s %14d %14s %10s  %s\n", name, base[name], "-", "-", "not measured"
			}
		}

		if (failed) {
			printf "\nbench: FAIL - a benchmark is more than %s%% slower than its baseline\n", tol > "/dev/stderr"
			exit 1
		}
		if (fresh) exit 3
		printf "\nbench: PASS - every benchmark is within %s%% of its baseline\n", tol
	}
' "$baseline_input" "$measured" || status=$?

{
	echo "# Push-latency numbers (R-012): benchmark name and ns/op."
	echo "#"
	echo "# Only comparable to a measurement from the same machine. CI measures"
	echo "# the parent commit into a file like this one and enforces the commit"
	echo "# under test against it, on that runner, in that job."
	echo "#"
	echo "# Recorded with: -benchtime=$BENCHTIME -count=$COUNT, best of $COUNT."
	cat "$measured"
} >"$CANDIDATE"

if [[ -n "$ADVISORY" && "$status" -eq 1 ]]; then
	# Advisory mode reports and stands down. It is for the comparison whose
	# baseline was taken on unknown hardware -- informative about drift, not
	# evidence of a regression -- and it deliberately still prints the table
	# and the REGRESSION rows above, because the number is worth seeing.
	echo "bench: advisory -- reporting the difference above without failing the build"
	status=0
fi

case "$status" in
0)
	exit 0
	;;
3)
	echo
	echo "bench: no baseline for the benchmarks marked \"new\". Measured numbers:"
	echo
	cat "$CANDIDATE"
	echo
	echo "bench: written to $CANDIDATE. Enforce against them by passing that file"
	echo "bench: as the baseline of a later comparison -- which is what CI does with"
	echo "bench: the parent commit's numbers, on the same runner, in the same job."
	exit 0
	;;
*)
	exit "$status"
	;;
esac
