#!/usr/bin/env bash
#
# Enforce the project coverage gate (CLAUDE.md section 9).
#
# Reads a Go coverage profile, drops the excluded files from the denominator,
# and fails if the remaining line coverage is below the threshold.
#
# Excluded from the denominator -- nothing else:
#   * cmd/*/main.go     process wiring
#   * *_mock.go         generated mocks
#   * *.gen.go          generated code
#   * the named shared contract harnesses: metatest, blobtest, verbtest,
#     clienttest. Named rather than matched as */*test/*, because that glob
#     also caught internal/archtest -- an analyser with real logic, not a
#     harness -- and silently dropped it from the denominator. Adding a harness
#     here is a deliberate, reviewable edit.
#   * test/*            the top-level test tree
#
# Usage: scripts/coverage.sh [profile] [threshold]

set -euo pipefail

PROFILE="${1:-coverage.out}"
THRESHOLD="${2:-95.0}"

if [[ ! -f "$PROFILE" ]]; then
	echo "coverage: profile not found: $PROFILE" >&2
	exit 2
fi

# A profile with only a mode line covers nothing; that is a failure, not a pass.
if [[ "$(wc -l <"$PROFILE" | tr -d '[:space:]')" -le 1 ]]; then
	echo "coverage: profile $PROFILE contains no coverage data" >&2
	exit 2
fi

# Profile lines are: file.go:from.col,to.col numStmts count
#
# With -coverpkg=./... every test binary emits blocks for every package, so the
# same block appears once per binary. Counts must be merged by block before
# anything is totalled, exactly as "go tool cover" does -- summing the raw lines
# instead would count a block once per test binary and understate coverage.
read -r covered total excluded_files < <(
	awk '
		NR == 1 && $0 ~ /^mode:/ { next }
		{
			block = $1
			file = block
			sub(/:.*/, "", file)
			if (file ~ /\/cmd\/[^\/]+\/main\.go$/ ||
			    file ~ /_mock\.go$/ ||
			    file ~ /\.gen\.go$/ ||
			    file ~ /\/(metatest|blobtest|verbtest|clienttest)\// ||
			    file ~ /\/test\//) {
				excluded[file] = 1
				next
			}
			stmts[block] = $(NF - 1)
			count[block] += $NF
		}
		END {
			for (b in stmts) {
				total += stmts[b]
				if (count[b] > 0) covered += stmts[b]
			}
			print covered + 0, total + 0, length(excluded)
		}
	' "$PROFILE"
)

if [[ "$total" -eq 0 ]]; then
	echo "coverage: no statements left after exclusions; refusing to pass" >&2
	exit 2
fi

percent=$(awk -v c="$covered" -v t="$total" 'BEGIN { printf "%.1f", (c / t) * 100 }')

printf 'coverage: %s%% of %s statements (%s covered, %s file(s) excluded), threshold %s%%\n' \
	"$percent" "$total" "$covered" "$excluded_files" "$THRESHOLD"

if awk -v p="$percent" -v th="$THRESHOLD" 'BEGIN { exit !(p + 0 < th + 0) }'; then
	echo "coverage: FAIL - below the ${THRESHOLD}% gate" >&2
	exit 1
fi

echo "coverage: PASS"
