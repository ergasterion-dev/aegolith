# CLAUDE.md — Pylolith

Pylolith is an open-source, API-aware web application firewall library for Go. It does protocol checks, route-typed request validation and targeted attack detectors in microseconds, shipped as `net/http` and Fiber v2 middleware.

- Module: `github.com/ergasterion-dev/pylolith` (Apache-2.0)
- Spec (binding): `docs/superpowers/specs/2026-11-24-pylolith-v0.1-design.md`
- Core dependencies: stdlib + `github.com/corazawaf/libinjection-go` only. Fiber lives in `adapters/fiberv2` (own module).

## Anti-goals (failure even if it technically works)

1. Blocking real customers. A false positive is worse than a missed probe the backend would 404 anyway.
2. Adding milliseconds. Over-budget features are off by default or out.
3. Becoming a CRS clone: generic rules only where the field is free text.
4. Crashing the host process: no panic escapes the middleware; internal errors follow the configured fail-open/fail-closed.

Also: never log full request values (PII); use `model.Redact`. Never copy code from GPL/AGPL projects.

## Layout

```
pylolith.go, config.go        Firewall, New, Inspect, LoadConfig, Config
internal/model/               Action, Mode, Severity, Location, Category, Match, Decision, Request, Limits
internal/normalize/           decode, JSON walk, query/form/cookie parsing, multipart
internal/protocol/            protocol checks
internal/detect/              attack detectors and scanning
internal/policy/              route table and typed field validation
internal/engine/              engine pipeline
httpwaf/                      net/http middleware
adapters/fiberv2/             Fiber v2 middleware (separate module)
testdata/corpus/              attack and legitimate request corpus
```

## Commands

`make build test test-quick vet fmt fmt-check bench fuzz-quick corpus ci` (`ci` = fmt-check vet test corpus). Install the hook with `ln -sf ../../scripts/pre-commit .git/hooks/pre-commit`.

## Rules

- No GitHub Actions, ever. CI is `make ci` plus the pre-commit hook.
- Commit directly to `main` and `git push origin main` after every commit. No branches, PRs or worktrees. Conventional Commits.
- `.superpowers/` is scratch space and is gitignored; never commit it.
