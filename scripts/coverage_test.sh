#!/usr/bin/env bash
#
# Self-test for scripts/coverage.sh. Feeds it fixture profiles and asserts the
# exit codes, so the gate itself is not the one untested thing in the build.
#
# Usage: scripts/coverage_test.sh

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
gate="$script_dir/coverage.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

failures=0
M="github.com/steveokay/trove"

# assert <name> <expected-exit> <profile-file> [threshold]
assert() {
	local name="$1" want="$2" profile="$3" threshold="${4:-95.0}"
	local got=0
	"$gate" "$profile" "$threshold" >/dev/null 2>&1 || got=$?
	if [[ "$got" -eq "$want" ]]; then
		echo "ok   - $name"
	else
		echo "FAIL - $name: exit $got, want $want"
		failures=$((failures + 1))
	fi
}

# Fully covered: passes.
printf 'mode: atomic\n%s/internal/a/a.go:1.1,3.2 10 1\n' "$M" >"$tmp/full.profile"
assert "fully covered passes" 0 "$tmp/full.profile"

# 90%: below the 95 gate.
printf 'mode: atomic\n%s/internal/a/a.go:1.1,3.2 9 1\n%s/internal/a/a.go:5.1,6.2 1 0\n' \
	"$M" "$M" >"$tmp/low.profile"
assert "below threshold fails" 1 "$tmp/low.profile"

# Same 90% profile passes a lower bar - the threshold argument is honoured.
assert "threshold argument honoured" 0 "$tmp/low.profile" 85.0

# An uncovered cmd/*/main.go must not drag the number down.
printf 'mode: atomic\n%s/internal/a/a.go:1.1,3.2 10 1\n%s/cmd/trove/main.go:1.1,9.2 50 0\n' \
	"$M" "$M" >"$tmp/main.profile"
assert "cmd main.go excluded" 0 "$tmp/main.profile"

# Generated mocks and .gen.go files are excluded too.
printf 'mode: atomic\n%s/internal/a/a.go:1.1,3.2 10 1\n%s/internal/a/store_mock.go:1.1,9.2 40 0\n%s/internal/a/api.gen.go:1.1,9.2 40 0\n' \
	"$M" "$M" "$M" >"$tmp/gen.profile"
assert "mocks and generated code excluded" 0 "$tmp/gen.profile"

# Shared test harnesses are excluded: their assertion branches only run when an
# implementation is broken.
printf 'mode: atomic
%s/internal/a/a.go:1.1,3.2 10 1
%s/internal/meta/metatest/suite.go:1.1,9.2 80 0
%s/test/conformance/run.go:1.1,9.2 40 0
' 	"$M" "$M" "$M" >"$tmp/harness.profile"
assert "test harnesses excluded" 0 "$tmp/harness.profile"

# A package merely containing "test" in its name mid-path is still counted.
printf 'mode: atomic
%s/internal/attestation/verify.go:1.1,9.2 50 0
' "$M" >"$tmp/attest.profile"
assert "production package with test-like name still counted" 1 "$tmp/attest.profile"

# A non-main .go file named like a command must NOT be excluded.
printf 'mode: atomic\n%s/internal/cli/main.go:1.1,9.2 50 0\n' "$M" >"$tmp/notcmd.profile"
assert "internal main.go still counted" 1 "$tmp/notcmd.profile"

# Duplicate blocks (one per test binary under -coverpkg=./...) must be merged,
# not summed as separate statements: the block below is covered by the second
# binary and uncovered by the first, and the file is fully covered overall.
printf 'mode: atomic\n%s/internal/a/a.go:1.1,3.2 10 0\n%s/internal/a/a.go:1.1,3.2 10 1\n' \
	"$M" "$M" >"$tmp/dup.profile"
assert "duplicate blocks merged" 0 "$tmp/dup.profile"

# Degenerate inputs are errors, never silent passes.
printf 'mode: atomic\n' >"$tmp/empty.profile"
assert "empty profile is an error" 2 "$tmp/empty.profile"

printf 'mode: atomic\n%s/cmd/trove/main.go:1.1,9.2 50 0\n' "$M" >"$tmp/allexcluded.profile"
assert "everything excluded is an error" 2 "$tmp/allexcluded.profile"

assert "missing profile is an error" 2 "$tmp/does-not-exist.profile"

if [[ "$failures" -ne 0 ]]; then
	echo "$failures assertion(s) failed" >&2
	exit 1
fi
echo "all coverage-gate assertions passed"
