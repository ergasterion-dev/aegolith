# Aegolith v0.1.0-alpha.5 False Positives and G1b Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the alpha.4 prod-test false positives (`Mon; sleep 8`, `${order.total}`) and detect the base64 Java object on an unknown path (G1b), then release alpha.5.

**Architecture:** Small local changes in `internal/detect` (CmdI, SSTI) and the engine's path scanning, each test-first with corpus cases.

**Tech Stack:** Go 1.25, stdlib, libinjection-go.

**Spec:** `docs/superpowers/specs/2026-11-25-aegolith-alpha5-false-positives-design.md` (read it); earlier alpha.4 spec and plan for context.

## Global Constraints

- Repo root `~/Desktop/ergasterion-dev-my-open-source-org/aegolith`, directly on `main`; commit and `git push origin main` after EVERY commit; no branches/worktrees/PRs/GitHub Actions; never bypass the pre-commit hook.
- No private names, hosts, IPs or customer data in code, corpus, docs or commits (generic `/api/v1` paths only).
- Legit corpus 0 false positives (now 118; add new near-misses); attack gates now 128/132 generic and 129/132 API-aware (corpus_test.go constants): may only rise, set them to the real counts after regenerating (`testdata/corpus/README.md`).
- Detectors stay linear and bounded; p99 budget 50 us; `make perf` only when `uptime` load is below ~10, otherwise write "not re-measured".
- `make ci` exit 0 (exit code only; rerun once if a wall-clock test fails under load); `(cd adapters/fiberv2 && go test -race -count=1 ./...)`.
- Never model `fable`; pass `model` explicitly.

## Review Focus

- `; sleep 10`, `| sleep 10 |`, `&& sleep 10` still caught; `Mon; sleep 8`, `Gate 2; sleep 10`, `Good night; sleep 8` clean (Task 1).
- `${7*7}`, `${user.password}`, `${T(java.lang.Runtime)...}`, `${jndi:...}` keep their rules; `${order.total}`, `${user.name}`, `${file.txt}`, `${price}` clean (Task 2).
- G1b payload on an unknown path detected; a long legit path containing `rO0` or base64-like segments stays clean (Task 3).

### Task 1: CmdI one-word-prefix sleep
**Files:** Modify `internal/detect/injection.go` (`isCmdI`, `commandAt`, the `sleepArgAt` logic from alpha.4); Test `internal/detect/injection_test.go`, engine test if needed; corpus files.
**Interfaces:** consumes the alpha.4 `sleep` handling; produces no new exported API.
- [ ] Write failing tests `TestCmdISleepPrefix`: clean `Mon; sleep 8`, `Gate 2; sleep 10`, `Good night; sleep 8`, `Tired & sleep 8`; hits `; sleep 10`, `x| sleep 10 |`, `;sleep 10`, `a && sleep 10`, `1;sleep 5` (state which of the last ones you keep and why: a prefix with no blank before the operator is attack-shaped). RED, implement the smallest change matching the spec, GREEN.
- [ ] Add corpus attacks/legit near-misses, regenerate, raise gates to real counts; update the alpha.4 docs claim in `docs/threat-model.md` and `CHANGELOG.md` only in Task 4.
- [ ] `make ci` exit 0, adapter tests, commit `fix(detect): do not flag a one-word prefix before sleep as command injection`, push.

### Task 2: SSTI `${a.b}` member access
**Files:** Modify `internal/detect/injection.go` (`isELExpr`); Test `internal/detect/injection_test.go`; corpus files.
**Interfaces:** `isELExpr(in string) bool` keeps its signature; adds a sensitive-name set.
- [ ] Failing tests `TestSSTIELBenignMemberAccess`: clean `${order.total}`, `${user.name}`, `${file.txt}`, `${price}`, `${a.b.c}`; hits `${7*7}`, `${user.password}`, `${env.SECRET}`, `${user.getClass()}`, `${T(java.lang.Runtime).getRuntime()}`, `${''.class.forName('x')}` (judge each against the spec: a call on a member is attack-shaped, plain nouns are not). RED, implement, GREEN.
- [ ] Corpus, gates to real counts, `make ci`, adapter tests, commit `fix(detect): flag ${...} member access only for sensitive names, calls or arithmetic`, push.

### Task 3: G1b base64 Java object on an unknown path
**Files:** investigate `internal/engine/inputs.go` (`checkRoute`, path scan), `internal/detect/scan.go` (`mayContainAttack`, `ScanText`), `internal/detect/injection.go` (`hasJavaSerialized`); Test engine test + detect test; corpus.
- [ ] Reproduce: an unknown route path carrying `rO0AB...` (the base64 Java object used in the lab: any valid short serialized-object base64 such as `rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAB3CAAAABAAAAAAeA==` with and without the `/api/v1/probe/` prefix) gives only ROUTE-001; find the cause (e.g. `/`, `=` or `+` handling in the decoded path, the prefilter, or the path being cut at a segment) with a failing test first.
- [ ] Fix without making ordinary long legit paths match (add legit path near-misses to engine tests), GREEN, corpus case, gates to real counts, `make ci`, adapter tests, commit `fix(engine): detect a serialized Java object in an unknown route path (G1b)`, push.

### Task 4: Docs and release alpha.5
**Files:** `docs/threat-model.md`, `CHANGELOG.md`, `README.md`, `adapters/fiberv2/README.md`, `adapters/fiberv2/go.mod`/`go.sum`.
- [ ] Update threat-model/CHANGELOG/README for the three fixes and the real corpus counts (docs claims must match code; remove the alpha.4 line saying the sleep prefix is a false positive and replace with the new behaviour); `uptime` load below ~10 then `make perf` and `make bench` (best of 3) and update numbers, else say "not re-measured". `make ci`, `make fuzz-quick` exit 0. Commit `docs: alpha.5 changelog, threat model and corpus counts`, push.
- [ ] Tag core `v0.1.0-alpha.5` on that commit and push the tag; in `adapters/fiberv2` run `GOWORK=off GOPROXY=direct go get github.com/ergasterion-dev/aegolith@v0.1.0-alpha.5`, hand-review go.mod/go.sum, update install notes (`@v0.1.0-alpha.4` to `@v0.1.0-alpha.5`, "pins core"), `go test -race -count=1 ./...`, commit `release: pin adapter to core v0.1.0-alpha.5, update install notes`, push, tag `adapters/fiberv2/v0.1.0-alpha.5`, push the tag.
- [ ] Verify from a clean empty scratch module with `GOWORK=off` (`go get` both at alpha.5, build a tiny main that inspects `please send 1 UNION SELECT password FROM users--` and prints block). Report tags and SHAs.
