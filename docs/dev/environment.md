# Development environment

trove targets Linux in production, but the inner development loop runs natively on
whatever workstation you use — including Windows (decision Q25, revised 2026-09-01).
Linux CI is the authoritative gate; `make test-linux` gives you the same verdict
locally before you push.

## Prerequisites

| Tool | Version | Notes |
|---|---|---|
| Go | 1.25+ | `go.mod` pins the language version; newer toolchains are fine |
| golangci-lint | v1.64.8 | CI pins this exact version — match it to avoid surprises |
| GNU Make | 4.x | On Windows, use the Git Bash shell (the Makefile sets `SHELL := /bin/bash`) |
| Docker | any recent | Needed for `make test-linux` and, later, testcontainers-based tests |
| Node + pnpm | Node 20+ | Only for the web UI, from task U-001 onward |

## Everyday commands

```bash
make build            # build bin/trove
make test             # full suite, race detector on
make cover            # suite + enforce the >=95% coverage gate
make cover-html       # browse the coverage report
make cover-selftest   # verify the gate script itself
make lint             # go vet + golangci-lint
make test-linux       # full suite inside a Linux container (see below)
make help             # list every target
```

## The coverage gate

`scripts/coverage.sh` enforces CLAUDE.md §9: **≥95 % line coverage**, measured with
`-coverpkg=./...`. Only three things leave the denominator — `cmd/*/main.go`,
`*_mock.go`, and `*.gen.go` — and nothing else may be added without amending §9.

Two details worth knowing:

- Under `-coverpkg=./...` every test binary emits blocks for every package, so the
  same block appears once per binary. The gate merges blocks by position before
  totalling; summing raw profile lines would understate coverage badly.
- Degenerate inputs (missing profile, no data, everything excluded) exit 2 rather
  than passing. A gate that passes when it cannot measure is worse than no gate.

The script has its own test suite (`make cover-selftest`, run in CI before the gate
itself) covering the exclusion rules, the threshold boundary, block merging, and each
degenerate case.

## Platform differences and how we handle them

Production is Linux; development may not be. Three rules keep that honest:

1. **Anything Linux-specific is skipped, never faked.** Tests asserting POSIX file
   permission bits, case-sensitive path behaviour, or signal semantics guard with
   `runtime.GOOS` and call `t.Skip` with a reason. A skipped test on Windows is
   visible; a test quietly asserting the wrong thing is not.
2. **`make test-linux` runs everything for real.** It executes the suite inside
   `golang:1.25-bookworm` — the Debian-based official Go image, chosen because it
   already ships git, gcc, and make, so no custom Dockerfile is needed and it
   matches the CI runner's userland closely.

   ```
   docker run --rm \
     -v "$PWD":/src \
     -v trove-gocache:/root/.cache/go-build \
     -v trove-gomodcache:/go/pkg/mod \
     -v /var/run/docker.sock:/var/run/docker.sock \
     -w /src golang:1.25-bookworm make test
   ```

   The named volumes keep the Go build and module caches warm between runs (the
   first run is slow, later ones are not). The Docker socket is mounted so
   testcontainers-based tests can start sibling containers — MinIO, Postgres, and
   `registry:2` — from inside.

   Override the image with `make test-linux LINUX_IMAGE=golang:1.25-alpine` if you
   ever need a different base.
3. **CI decides.** A change is not done until Linux CI is green, whatever your
   workstation says.

### Windows specifics

- Run `make` from **Git Bash**, not PowerShell or cmd.
- The Makefile passes a Windows-style path to Docker via `pwd -W`, and sets
  `MSYS_NO_PATHCONV=1` so Git Bash does not rewrite container-side paths.
- Line endings are normalised to LF by `.gitattributes`; leave
  `core.autocrlf` alone.
- Long paths: enable `git config --global core.longpaths true` if you hit
  path-length errors on deeply nested test fixtures.
- **New shell scripts need their executable bit set in git explicitly.** Windows
  does not carry the mode bit, so `chmod +x` alone is invisible to git and the
  script lands in the repo as `100644` — Linux CI then fails with
  "Permission denied". Run:

  ```bash
  git update-index --chmod=+x scripts/your-script.sh
  ```

  As a belt-and-braces measure, the Makefile and CI invoke scripts as
  `bash scripts/x.sh` rather than `./scripts/x.sh`, so a missing bit cannot break
  the build.

## Repository layout

See `CLAUDE.md` §3 for the package map, `docs/adr/` for the binding design decisions,
`docs/plan/` for per-task implementation specs, and `status.md` for what is done and
what is next.
