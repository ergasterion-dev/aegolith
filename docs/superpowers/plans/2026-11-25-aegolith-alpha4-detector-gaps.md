# Aegolith v0.1.0-alpha.4 Detector Gaps Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close detector gaps G1-G8 found in the prod-lab test so Aegolith's text rules are safe to rely on in enforce mode, and ship it as `v0.1.0-alpha.4`.

**Architecture:** Each gap is a small, local change in `internal/detect` (G1-G7) or `adapters/fiberv2` (G8), driven test-first from the lab payloads. G1 adds a bounded rescan of the SQLi check from extra start offsets chosen at SQL-keyword and number tokens, because libinjection detects the attack when it starts at the keyword but not after leading words. The engine's existing overlapping 8 KiB windows already carry padded payloads, so the G1 fix per window covers G1c.

**Tech Stack:** Go 1.25 stdlib, `github.com/corazawaf/libinjection-go`, Fiber v2 adapter (separate module).

**Spec:** `docs/superpowers/specs/2026-11-25-aegolith-alpha4-detector-gaps-design.md`. Binding v0.1 spec: `docs/superpowers/specs/2026-11-24-aegolith-v0.1-design.md`. Gap evidence (payloads): the table in section "Detector gaps" of the plan's source, reproduced in each task below.

## Global Constraints

- Repo root `~/Desktop/ergasterion-dev-my-open-source-org/aegolith`; module `github.com/ergasterion-dev/aegolith`; core deps stdlib + libinjection-go only.
- Commit straight to `main`, `git push origin main` after EVERY commit. No branches, worktrees, PRs, GitHub Actions. Conventional Commits. Never bypass the pre-commit hook.
- The public repo must contain no QuickDrop names, hosts, IPs, customer data, in code, corpus, docs or commits. Use generic paths (`/api/v1/...`) only.
- False positives are worse than misses: legit corpus stays at **0 false positives of 91**; attack gates stay at least **103/107 generic and 104/107 API-aware** (they may only rise); run `go test -run Corpus -v .` and read the per-category tables.
- Latency: p99 under 50 us (last measured 10-21 us); every detector stays linear in input length; no per-request allocation growth on clean inputs. `make perf` only when `uptime` load is below ~10; never under `-race`.
- Never log full request values (use `model.Redact`). Never copy GPL/AGPL code.
- Never use model `fable`. Pass `model` explicitly to every subagent (opus for Task 1 and reviews, sonnet otherwise).
- `make ci` must exit 0 (check exit code only, do not pipe it); adapter tests: `(cd adapters/fiberv2 && go test -race -count=1 ./...)`.

## Review Focus

- Legit prose that reads like a G1 suffix (`please union select the best one`, `select a seat`, `1 or 2 tickets`, `order by price`, `drop me a line`) must stay clean: tested in Task 1.
- Very long values (100k chars of repeated `select 1 union ` and of `;copy(`) must not blow up time: linear-time test in Task 1.
- Prose containing `{{define}}`-like words or `${PRICE}` / `${total}` placeholders (legit templates in notes) must stay clean: Task 3.
- Legit text with quotes or backslashes (`it's`, `C:\\temp`, `don't`) and `sleep` used in prose (`; sleep well`) must stay clean: Task 4.
- Legit paths and UAs (`/api/v1/environment`, `/api/v1/actuators-list`, a UA containing `hydra` as part of a longer word like `Hydration`) must stay clean: Task 5.
- Legit JSON/form keys with spaces, quotes, `$` currency names (`amount[$USD]`), and long keys: Task 6.

---

### Task 1: G1 SQL injection after leading words (also G1b, G1c)

**Files:**
- Modify: `internal/detect/sqlixss.go` (`isSQLi`)
- Test: `internal/detect/sqlixss_test.go`
- Corpus: `testdata/corpus/attacks.jsonl` (+ `source/attacks.sh` / `gen.sh` per `testdata/corpus/README.md`), `testdata/corpus/legit.extra.jsonl`
- Test (engine, padding + unknown-path): `internal/engine/engine_test.go` or `aegolith_test.go`, whichever holds the PROTO-011 window tests

**Interfaces:**
- Consumes: `libinjection.IsSQLi(s) (bool, string)`, `isProseNumberComment(s, fp string) bool`, `valueOrDecoded(v, f)` (existing).
- Produces: `func sqliFromKeywordStarts(s string) bool` in `sqlixss.go`, called by `isSQLi` when the plain check and `hasStackedCopyProgram` both miss. Constant `maxSQLiStarts = 8` (cap on extra starts per value).

- [ ] **Step 1: Write failing tests** in `sqlixss_test.go`: `TestSQLiAfterLeadingWords` asserts `SQLi` reports a hit for `please send 1 UNION SELECT password FROM users--`, `milk 1; DROP TABLE orders;--`, `b b b b b b 1 UNION SELECT password FROM users--`, and for the same payload preceded by 20,000 characters of `a`/`b ` (through `ScanText`). `TestSQLiProseStaysClean` asserts no hit for the Review Focus prose in the Global/Review lists above plus `O'Brien union select`, `select * from menu`, `order by price`. `TestSQLiStartsLinear` asserts 200k chars of `select 1 union ` and of `1 or ` finish within a generous bound comparable to existing linear tests in `scan_test.go`.
- [ ] **Step 2: Run** `go test ./internal/detect -run 'SQLiAfterLeadingWords|SQLiProse|SQLiStartsLinear' -v`. Expected: the first FAILS, the other two pass.
- [ ] **Step 3: Implement `sqliFromKeywordStarts(s string) bool`** in `sqlixss.go`: scan s once; at most `maxSQLiStarts` positions that begin a word or number token right after whitespace or `;` and whose token is a number or a case-insensitive SQL keyword start (`union`, `select`, `drop`, `insert`, `update`, `delete`, `or`, `and`, `waitfor`, `exec`, `declare`, `1`-`9`), run `libinjection.IsSQLi(s[start:])` and apply `isProseNumberComment`. Starts must be chosen so total libinjection work stays linear (each call bounded by len(s) and `maxSQLiStarts` caps the count; document this). Wire into `isSQLi`. Prose guard: a suffix hit is accepted only if it contains a SQL statement shape libinjection fingerprints, not a lone keyword; add any further guard needed to keep Step 1's prose list clean.
- [ ] **Step 4: Run** the three tests plus `go test -run Corpus -v .`; confirm 0 FP of 91 and attack gates not lower.
- [ ] **Step 5: Engine tests:** add to the engine test file a case that an unknown-route path `/api/v1/probe/1 UNION SELECT username, password FROM users--` (decoded) yields SQLI-001, and a JSON field with 20,000 chars of padding then ` 1 UNION SELECT password FROM users--` yields SQLI-001 (not only AEG-PROTO-011).
- [ ] **Step 6: Corpus:** add the G1 payloads as attacks (query and JSON locations) and add the prose near-misses to `legit.extra.jsonl`; regenerate per `testdata/corpus/README.md`; update gate constants in `corpus_test.go` only upward and only to match the real new counts.
- [ ] **Step 7: Verify and commit:** `make ci` exit 0; `(cd adapters/fiberv2 && go test -race -count=1 ./...)`; `git add` the changed paths; `git commit -m "fix(detect): SQL injection after leading words and padding (G1)"`; `git push origin main`.

---

### Task 2: G2 nested broken script tag

**Files:** Modify `internal/detect/sqlixss.go` (`isXSS`); Test `internal/detect/sqlixss_test.go`; corpus files as in Task 1.

**Interfaces:** Produces `func hasScriptTagAnywhere(s string) bool` (case-insensitive `<script` followed by `>`, `/`, whitespace, or another `<`), used by `isXSS`.

- [ ] **Step 1: Failing tests:** `TestXSSNestedScriptTag`: hit for `<scr<script>ipt>alert(1)</script>`, `<SCR<script >ipt>`; no hit for `a < script is a word`, `1<scripts`, `price <script` prose without a closing shape (decide the minimal boundary rule so these stay clean; include them as clean cases).
- [ ] **Step 2:** run, expect FAIL for the first.
- [ ] **Step 3:** implement and wire into `isXSS`; linear scan (use existing `indexFold`).
- [ ] **Step 4:** corpus run (0/91 FP, gates not lower); add attack + prose near-miss to corpus.
- [ ] **Step 5:** `make ci`; commit `fix(detect): flag nested script tags (G2)`; push.

---

### Task 3: G3 Go template actions and EL expressions

**Files:** Modify `internal/detect/injection.go` (`isCodeExpr`, `isSSTI`, `isHashExpr` region); Test `internal/detect/injection_test.go`; corpus files.

**Interfaces:** Extends `isCodeExpr(in string) bool` with Go action keywords as first word (`printf`, `call`, `define`, `template`, `index`, `html`, `js`, `block`, `with`, `range`, `slice`) followed by blank/`}`/`.`; adds `func isELExpr(in string) bool` for `${...}` with operators (`*`, `+` between numbers), member access (`user.password`) or a call, wired into `isSSTI` via `eachDelimited(s, "${", "}", isELExpr)`.

- [ ] **Step 1: Failing tests:** `TestSSTIGoActionsAndEL`: hits for `{{printf "%v" .}}`, `{{ call .Func }}`, `{{define "x"}}{{.}}{{end}}`, `{{ printf "%s" .Secret }}`, `${7*7}`, `${user.password}`. Clean: `${PRICE}`, `${total}`, `{{ best price }}`, `{{name}}`, `{{ index }}` alone as a prose word, `${5}`.
- [ ] **Step 2:** run, expect FAIL.
- [ ] **Step 3:** implement; also check `mayContainAttack` already admits `{`/`$` (it does); no prefilter change needed.
- [ ] **Step 4:** corpus run; add attacks and prose near-misses; confirm 0/91.
- [ ] **Step 5:** `make ci`; commit `fix(detect): flag Go template actions and EL expressions (G3)`; push.

---

### Task 4: G4 command injection variants

**Files:** Modify `internal/detect/injection.go` (`isCmdI`, `commandAt`, `CmdI`); Test `internal/detect/injection_test.go`; corpus files.

**Interfaces:** Produces `func dequoteShellWord(s string) string` (drops `'`, `"` and `\` that split words, only used for matching the command word, linear). Adds `sleep` to the known-command table used by `commandAt`.

- [ ] **Step 1: Failing tests:** `TestCmdIVariants`: hits for `x%0aid`, `; sleep 10`, `;w'h'o'am'i`, `;c\at /et\c/pas\swd`. Clean: `Notes:\nls`-style literal prose (existing), `rest; sleep well`, `it's; fine`, `C:\temp\notes`, `Tea & sleep 8 hours`.
- [ ] **Step 2:** run, expect FAIL for the four hits.
- [ ] **Step 3:** implement. `x%0aid`: after percent-decoding, a newline followed by a bare known command is accepted only because the line break was encoded (existing `hasEncodedLineBreak` rule); fix the reason `id` is missed (likely `id` needs an argument or end-of-value rule) without loosening literal-newline prose rule. `sleep` requires a numeric argument.
- [ ] **Step 4:** corpus run; add attacks and prose near-misses; 0/91.
- [ ] **Step 5:** `make ci`; commit `fix(detect): flag command injection variants (G4)`; push.

---

### Task 5: G5 probe paths under a prefix, G6 scanner user agents

**Files:** Modify `internal/detect/scanner.go` (`ProbePath`, `isProbePrefix`, `UserAgent`); Test `internal/detect/scanner_test.go`; engine test if call site changes (`internal/engine/inputs.go:19`).

**Interfaces:** `ProbePath(p string) (Hit, bool)` additionally matches the probe names (`/.env`, `/.git/`, `/.aws/`, `/.ssh/`, `/actuator`, `/wp-admin`, `/phpmyadmin`, `/server-status`, `/wp-login.php`) at the start of ANY path segment (preceded by `/`), same terminator rules as today. `UserAgent` token list gains `wfuzz`, `feroxbuster`, `hydra`, and the phrase `fuzz faster u fool` (case-insensitive).

- [ ] **Step 1: Failing tests:** `TestProbePathUnderPrefix`: hits for `/api/v1/.env`, `/api/v1/.git/config`, `/api/v1/actuator/env`. Clean: `/api/v1/environment`, `/api/v1/actuators-list`, `/api/v1/orders/envelope`, `/api/v1/wp-admins-are-us`. `TestUserAgentFuzzers`: hits for `Fuzz Faster U Fool v2.1.0-dev`, `Wfuzz/3.1.0`, `feroxbuster/2.10.4`, `Hydra`. Clean: `Hydration/1.0`, `Mozilla/5.0 ... Chrome`.
- [ ] **Step 2:** run, expect FAIL. **Step 3:** implement (linear; reuse `hasPrefixFold` and `hasLetterWordFold`). **Step 4:** corpus run, 0/91; add attacks. **Step 5:** `make ci`; commit `fix(detect): scanner probe paths under a prefix and fuzzer user agents (G5, G6)`; push.

---

### Task 6: G7 injection in key names

**Files:** Modify `internal/detect/keys.go` (`QueryKey`, `JSONKey`) and call sites `internal/engine/inputs.go:133, 232, 279`; Test `internal/detect/keys_test.go`, engine test; corpus files.

**Interfaces:** Key names are also passed through `SQLi` (rule `AEG-SQLI-001`) and prototype-pollution is recognized in bracket/dot form: `QueryKey` also reports `AEG-PPOLL-001` for a key whose segments (split on `[`, `]`, `.`) include `__proto__`, `constructor` or `prototype`. Key text is passed through `s.capped` before scanning (existing helper) so cost stays bounded.

- [ ] **Step 1: Failing tests:** keys_test: `QueryKey("__proto__[isAdmin]")` is a hit (PPOLL-001); `QueryKey("a.constructor.prototype.x")` hit. Engine tests: JSON body `{"1' OR '1'='1":1}` yields SQLI-001 with field naming the key (no value snippet), query `?1' OR '1'='1=x` yields SQLI-001. Clean: keys `first name`, `user's note`, `amount[$USD]`, `constructor_year`, `prototype_id`.
- [ ] **Step 2:** run, expect FAIL. **Step 3:** implement. **Step 4:** corpus run, 0/91 (corpus legit keys must stay clean); add attacks. **Step 5:** `make ci`; commit `fix(detect): inspect key names for injection and bracket prototype pollution (G7)`; push.

---

### Task 7: G8 adapter over-cap body in monitor

**Files:** Modify `adapters/fiberv2/middleware.go` (body copy near line 78 and 180); possibly `internal/engine/inputs.go` for PROTO-020 on truncated bodies; Test `adapters/fiberv2/middleware_test.go`, engine test.

**Interfaces:** Consumes `Firewall.Limits().MaxBodyBytes` and the engine's documented over-cap inspection limit (2 x MaxBodyBytes; read the constant `bodyInspectLimit` in `internal/engine`). If it is unexported, expose an accessor on `Firewall` (`func (f *Firewall) BodyInspectLimit() int`, additive, not breaking) so the adapter copies up to that limit only when PROTO-003 is not blocking (monitor mode), else keeps `MaxBodyBytes+1`.

- [ ] **Step 1: Failing tests:** adapter test in monitor mode: a 1.5 MiB JSON body (default cap 1 MiB) with `1 UNION SELECT` near the end yields SQLI-001 plus PROTO-003, and does not yield AEG-PROTO-020 when the only reason is truncation. In enforce mode the same request is still blocked by PROTO-003 and the copy stays at `MaxBodyBytes+1` (assert via a body larger than the 2x limit that memory use is bounded: test the copy length through a seam or by behavior).
- [ ] **Step 2:** run, expect FAIL. **Step 3:** implement; keep the handler's view of the body untouched. **Step 4:** `(cd adapters/fiberv2 && go test -race -count=1 ./...)` and `make ci`. **Step 5:** commit `fix(fiberv2): inspect over-cap bodies up to the engine limit in monitor (G8)`; push.

---

### Task 8: Docs, perf, fuzz

**Files:** Modify `docs/threat-model.md`, `CHANGELOG.md`, `README.md`, `docs/architecture.md` if rule behavior is described there.

- [ ] **Step 1:** `make ci` exit 0; `go test -run Corpus -v .` and record the new real counts; `make fuzz-quick` exit 0.
- [ ] **Step 2:** check `uptime`; if load is below ~10 run `make perf` and `make bench` (best of 3) and record numbers; otherwise record "not re-measured" in the CHANGELOG and do NOT edit README benchmark numbers.
- [ ] **Step 3:** Update `docs/threat-model.md` (G1-G8 now covered; G9 listed as known unsupported: MySQL-only syntax, fullwidth/`%u`/overlong encodings, nip.io SSRF, XPath, Python `__import__`; new recall/precision costs found while testing, e.g. any prose that the new rules flag), `CHANGELOG.md` (an `alpha.4` entry), and README counts from real runs only. No QuickDrop names.
- [ ] **Step 4:** commit `docs: alpha.4 changelog, threat model and corpus counts`; push.

---

### Task 9: Release alpha.4

**Files:** Modify `adapters/fiberv2/go.mod`, `adapters/fiberv2/go.sum`, README install notes; tags.

- [ ] **Step 1:** `git fetch`; confirm `main` equals `origin/main`, `make ci` exit 0 and adapter tests pass. Tag core: `git tag v0.1.0-alpha.4 && git push origin v0.1.0-alpha.4`.
- [ ] **Step 2:** In `adapters/fiberv2`: `GOPROXY=direct go get github.com/ergasterion-dev/aegolith@v0.1.0-alpha.4` (no `replace`), hand-review the `go.mod`/`go.sum` diff, `go test -race -count=1 ./...`; update README install notes; commit `release: pin adapter to core v0.1.0-alpha.4`; push; tag `adapters/fiberv2/v0.1.0-alpha.4` and push it.
- [ ] **Step 3:** Verify from a clean scratch module: in a brand-new empty directory under the scratchpad, `go mod init scratch`, `GOPROXY=direct go get github.com/ergasterion-dev/aegolith@v0.1.0-alpha.4 github.com/ergasterion-dev/aegolith/adapters/fiberv2@v0.1.0-alpha.4`, build a tiny main that imports both and inspects one G1 payload. Pass paths as arguments; do not run tools inside untrusted directories. Expected: builds and detects.
- [ ] **Step 4:** Report the tags and commit SHAs. (The QuickDrop bump, prod release and lab re-test follow in separate steps outside this public repo; they are not part of this plan.)

---

## Self-Review

- Spec coverage: G1/G1b/G1c Task 1, G2 Task 2, G3 Task 3, G4 Task 4, G5 and G6 Task 5, G7 Task 6, G8 Task 7, docs/perf Task 8, release order Task 9. G9 documented in Task 8.
- Names consistent: `sqliFromKeywordStarts`, `maxSQLiStarts`, `hasScriptTagAnywhere`, `isELExpr`, `dequoteShellWord`, `BodyInspectLimit` used only where defined.
- Review Focus lines each map to a test in Tasks 1, 3, 4, 5, 6.
