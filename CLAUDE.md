# CLAUDE.md — Aegolith

Aegolith is an open-source, API-aware web application firewall library for Go. It does protocol checks, route-typed request validation and targeted attack detectors in microseconds, shipped as `net/http` and Fiber v2 middleware.

- Module: `github.com/ergasterion-dev/aegolith` (Apache-2.0)
- Spec (binding): `docs/superpowers/specs/2026-11-24-aegolith-v0.1-design.md`
- Core dependencies: stdlib + `github.com/corazawaf/libinjection-go` only. Fiber lives in `adapters/fiberv2` (own module).

## Anti-goals (failure even if it technically works)

1. Blocking real customers. A false positive is worse than a missed probe the backend would 404 anyway.
2. Adding milliseconds. Over-budget features are off by default or out.
3. Becoming a CRS clone: generic rules only where the field is free text.
4. Crashing the host process: no panic escapes the middleware; internal errors follow the configured fail-open/fail-closed.

Also: never log full request values (PII); use `model.Redact`. Never copy code from GPL/AGPL projects.

## Layout

```
aegolith.go, config.go        Firewall, New, Inspect, LoadConfig, Config; type aliases for the public API
example_test.go               compiled README examples (core)
internal/model/               Action, Mode, Severity, Location, Category, Match, Decision, Request, Limits, Redact
internal/normalize/           decode, JSON walk, query/form/cookie parsing, multipart
internal/protocol/            protocol checks (AEG-PROTO-001..007)
internal/detect/              attack detectors, ScanText and its prefilter, scanner rules, key rules
internal/policy/              route table and typed field validation
internal/engine/              pipeline, scan budget, exclusions, decisions
httpwaf/                      net/http middleware and the slog hook
adapters/fiberv2/             Fiber v2 middleware (separate module, own go.mod)
testdata/corpus/              attack and legitimate request corpus (attacks.jsonl, legit.jsonl, policy, gen.sh)
scripts/                      pre-commit hook, fuzz-quick.sh (discovers and runs every Fuzz target)
docs/                         architecture.md, threat-model.md; docs/superpowers has the spec and plans
```

Tests: `corpus_test.go` (the two corpus gates), `bench_test.go` (benchmarks and the latency budget), `timing_test.go`, `fuzz_test.go`.

## Commands

| Target | What it does |
|---|---|
| `make build` | `go build ./...` (CGO off) in the core and the adapter |
| `make test` | `go test -race ./...` then plain `go test ./...`, in both modules (both runs are needed: some growth-ratio checks are skipped under `-race`) |
| `make test-quick` | plain `go test ./...` in both modules (what the pre-commit hook runs) |
| `make vet`, `make fmt`, `make fmt-check` | `go vet`; `gofmt -w` or check on tracked and untracked Go files |
| `make bench` | `go test -run '^$' -bench . -benchmem ./...` in both modules |
| `make perf` | latency budget with `AEGOLITH_PERF=1` (p99 < 50 us); never under `-race` |
| `make fuzz-quick` | every Fuzz target for `FUZZTIME` (default 10s) via `scripts/fuzz-quick.sh` |
| `make corpus` | `go test -run Corpus -v .`: per-category tables, misses, false positives |
| `make ci` | `fmt-check vet test corpus` |

Wall-clock bounds are strict only with `AEGOLITH_PERF=1` and are skipped under `go test -short`. Install the hook with `ln -sf ../../scripts/pre-commit .git/hooks/pre-commit` (it runs `make fmt-check vet test-quick`); never bypass it.

## Rules

- No GitHub Actions, ever. CI is `make ci` plus the pre-commit hook.
- Commit directly to `main` and `git push origin main` after every commit. No branches, PRs or worktrees. Conventional Commits.
- `.superpowers/` is scratch space and is gitignored; never commit it.
- Public repo: no private hostnames, IPs, customer data or personal details in code, docs, corpus or commits.
- Docs: README numbers come from real runs (`make corpus`, `make bench` best of 3, `make perf`); code snippets in docs are compiled as `example_test.go`.
