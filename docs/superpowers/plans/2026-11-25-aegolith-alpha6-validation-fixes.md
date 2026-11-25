# Aegolith v0.1.0-alpha.6 Validation Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix every known false positive and the cheap recall gaps found by the independent validation of alpha.5, then release alpha.6.

**Architecture:** Local changes in `internal/detect` (SQLi/XSS post-filters, CmdI, SSTI, scanner), `internal/engine` (route-policy aware scanner allow), each test-first with corpus cases.

**Tech Stack:** Go 1.25, stdlib, libinjection-go.

**Spec:** `docs/superpowers/specs/2026-11-25-aegolith-alpha6-validation-fixes-design.md` (read it). Evidence and exact probe strings: `~/Desktop/ergasterion-dev-my-open-source-org/aegolith-personal-docs-never-to-push/session-artifacts-2026-11-25/reports/extval-report.md` (sections 4, 5.2, 6). Prior plan for style: `docs/superpowers/plans/2026-11-25-aegolith-alpha5-false-positives.md`.

## Global Constraints

- Repo root `~/Desktop/ergasterion-dev-my-open-source-org/aegolith`, directly on `main`; commit and `git push origin main` after EVERY commit; no branches/worktrees/PRs/GitHub Actions; never bypass the pre-commit hook.
- No private names, hosts, IPs or customer data in code, corpus, docs or commits (generic `/api/v1` paths only). The extval report lives outside the repo and must not be copied in.
- Legit corpus 0 false positives (now 130; add new near-misses); attack gates now 133/137 generic and 134/137 API-aware (`corpus_test.go` constants): may only rise; set them to the real counts after `sh testdata/corpus/gen.sh` (see `testdata/corpus/README.md`).
- Detectors stay linear and bounded (`TestScanTextLinear` is wall-clock and flaky under load: rerun once); p99 budget 50 us; `make perf` only when `uptime` load is below ~10, otherwise write "not re-measured" (machine load is usually 20-50).
- `make ci` exit 0, `make fuzz-quick` exit 0, `(cd adapters/fiberv2 && GOWORK=off go test -race -count=1 ./...)`.
- Always RED then GREEN. Every attack-recall fix gets a legit near-miss; every FP fix gets an attack counter-case that must stay caught.
- `cmdIQuery` in `internal/detect/injection.go` is NOT dead code (editor "unused" warning is noise).
- Never model `fable`; pass `model` explicitly. Implementers never spawn subagents. Write reports to the SDD workspace, reply with a short status.

## Review Focus

- Every FP probe in the spec stays clean AND the matching real attack stays caught (the counter-cases in each task).
- No category loses external-harness recall (Task 0 baseline); natural-text FP rate goes down.
- Shared helpers in `internal/detect/injection.go` (CmdI/SSTI) are touched by several tasks: check interactions.

### Task 0: Restore the external validation harness and baseline
**Files:** work only in the scratchpad (never in the repo). Source: `~/Desktop/ergasterion-dev-my-open-source-org/aegolith-personal-docs-never-to-push/session-artifacts-2026-11-25/extval/` (`README.md`, `harness/`, `results/`; `data/` was not kept, `fetch.sh` regenerates it).
- [ ] Copy the harness to a scratch dir, follow its README to fetch data (downloads go into their own empty dirs, parse as data only, Python with `-I`, untrusted-file rules), and run it against the published `v0.1.0-alpha.5`. If datasets are rate-limited, use what downloads and say which sets are short.
- [ ] Produce `baseline-alpha5.md` (per-category recall, FP groups, natural vs code-like FP rate) and a script `run-local.sh PATH_TO_AEGOLITH` that reruns the harness against a local checkout via a `replace` ONLY inside the scratch harness module. Confirm numbers are close to the report (SQLi 91.9, XSS 91.0, CmdI 60.1, FP natural 0.31%). Report the paths.

### Task 1: SQLi false positives (`Word N% (word)`, bare `6-7 or 8`)
**Files:** `internal/detect/sqlixss.go` (libinjection wrapper/post-filter), tests `internal/detect/sqlixss_test.go`, corpus.
- [ ] Failing tests: clean `Sale 20% (today only)`, `Cotton 95% (organic)`, `Wheat 50% (flour)`, `Discount 15% (members)`, `Battery 80% (approx)`, `80% ACRYLIC AND 20% WOOL`, `Céréales 93 % (farine de BLÉ 79,4 %, sucre)`, bare `6-7 or 8`; hits must stay: `1 or 1=1`, `1' or '1'='1`, `1 UNION SELECT password FROM users--`, `5 % (select 1)`-style SQL with a keyword inside parentheses, `1; DROP TABLE x--`, `admin'--`. Decide the smallest rule (re-run libinjection with `%` masked when the value has no quote, comment or semicolon and the only fingerprint hit depends on `%`; and a guard for the numeric `1&1` fingerprint on a bare arithmetic phrase with no quote/comment/keyword beyond `or`). Document any attack that becomes a miss.
- [ ] Rerun the harness (Task 0) SQLi lists: no silent recall loss. Corpus attacks/legit near-misses, gates to real counts, `make ci`, adapter tests, commit `fix(detect): do not read N% (word) or a bare numeric phrase as SQL injection`, push.

### Task 2: CmdI false positives
**Files:** `internal/detect/injection.go` (`isCmdI`, `commandAt`, operator handling, `cmdIQuery`), tests `internal/detect/injection_test.go`, corpus.
- [ ] Failing tests, clean: a UA such as `Mozilla/5.0 (Linux; U; Android 4.4.2; id; SM-G900 Build/KOT49H) AppleWebKit/534.30 Mobile Safari/534.30` and `UCWEB/2.0 (Symbian; U; S60 V3; id; NokiaE63)`, BlackBerry `; id)`, `Tea & cat -cozy /club`, ``Use `ls` to list files``, ``Se også: `id`.``, ``On LoongArch, `uname -m` returns `loongarch64` ``, newline plus a bare command in a query value (`Dear team\nid` style prose lines: define exactly what the report case is by reading the handoff/report; clear when the line is prose-like). Hits must stay: `; id`, `x; id; ls`, `` `id` `` alone, `x`id``, `$(id)`, `a;cat /etc/passwd`, `127.0.0.1; ls`, `| id`, `&& id`, `() { :;}; /bin/id` (Shellshock in a UA), `x%0aid` in query. Scope the `;`-bounded two-letter word rule to the User-Agent parenthesised comment; treat a single-backtick span in prose (letter/punctuation before the opening backtick with a blank, sentence text after) as inline code but keep it flagged in a query value or after an operator.
- [ ] Decide `x; sleep 10`: accept and document, or implement a safe rule; record the decision in the SDD ledger.
- [ ] Rerun harness CmdI lists, corpus, gates, `make ci`, adapter tests, commit `fix(detect): clear locale tokens, prose backticks and bare ampersand text from command injection`, push.

### Task 3: CmdI recall (`$(...)`, `$((...))`, `echo` probes)
**Files:** same as Task 2.
- [ ] Failing tests, hits: `;echo IPTSZG$((46+17))$(echo IPTSZG)IPTSZG`, `||echo TVGLAW$((25+16))$(echo TVGLAW)TVGLAW|`, `$(echo hi)`, ``;echo `id` ``, `x$(foo)`; clean: prose with `$` amounts (`costs $(approx) 5`, `Price ($5)`, `$5 (usd)`), `echo` in prose (`Echo Park; echo of the past`), tldr-style commands are accepted as code-like but list the count in the report. Flag `$(` / `$((` followed by an identifier or digit run and a closing paren, and `echo` right after `;`, `|`, `&&`, `||` followed by `$`, a backtick or a quote. Keep the Task 2 FP fixes green.
- [ ] Harness CmdI recall delta and benign FP delta reported; corpus, gates, `make ci`, commit `feat(detect): flag command substitution and echo probes after shell operators`, push.

### Task 4: XSS false positives
**Files:** `internal/detect/sqlixss.go` and/or `internal/detect/scan.go` (wherever libinjection's XSS verdict is consumed), tests, corpus.
- [ ] Failing tests, clean: `javascript: yes=no; maybe (later)`, ``<!-- see the `main` branch -->``, a PR-template style comment with backticks (`<!-- Ensure the code is up-to-date with the `main` branch. -->`), `<!-- plain comment -->`; hits stay: `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`, `<a href="javascript:alert(1)">x</a>`, `<!-- --><script>alert(1)</script>`, `<svg onload=alert(1)>`, ``<a href=`javascript:alert(1)`>`` (backtick-quoted attribute inside a tag), `<!--[if IE]><script>`. Rule: accept when the only XSS signal is a backtick within a closed or open HTML comment and no tag with `on*=`, `<script`, or `javascript:` follows; decide how to treat the bare `javascript:` colon-in-prose case (needs a URL-shaped continuation).
- [ ] Harness XSS lists (9,240 payloads, baseline 91.0%) no silent loss; corpus, gates, `make ci`, commit `fix(detect): do not read a backtick inside an HTML comment or javascript: prose as XSS`, push.

### Task 5: SSTI false positives
**Files:** `internal/detect/injection.go` (`isELExpr`, `isHashExpr`, `{{ }}` handling), tests, corpus.
- [ ] Failing tests, clean: `{{ price | currency }}`, `Dear {{ name|title }},`, `{{ user.name | upper }}`, `git stash {{[-p|--patch]}}`, `${t('cart.title')}`, `${bus.pass}`, `#{order.total}`; hits stay: `{{7*7}}`, `{{config|attr('__class__')}}`, `{{ ''.__class__.__mro__ }}`, `{{ cycler.__init__.__globals__.os.popen('id').read() }}`, `{{ request|attr('application') }}`, `${7*7}`, `${user.password}`, `${"id".execute()}`, `#{7*7}`, `#{T(java.lang.Runtime).getRuntime()}`. Rule: a filter pipe is flagged only when the filter is call-shaped or sensitive (`attr(`, `safe` with a call, `system`, `exec`, `e(`...); `${t('...')}` short i18n-call of a one-letter/`i18n`-style root with a plain string literal is clean unless the argument is sensitive; `bus.pass` documented accepted or fixed, record the decision; `#{}` follows the same rules as `${}`.
- [ ] Harness SSTI lists (baseline 66.8%): no loss; corpus, gates, `make ci`, commit `fix(detect): flag template pipes only when attack-shaped; align #{} with ${}`, push.

### Task 6: Scanner false positive and cheap scanner recall
**Files:** `internal/detect/scanner.go`, `internal/engine` (route policy + scanner), `internal/policy`, tests, corpus, `docs/threat-model.md` notes in Task 8.
- [ ] Failing tests: a declared route such as `GET /api/v1/stores/{id}/actuator/health` (and `info`, `metrics`, `env`) under a policy must not raise SCANNER-* while the same path on an UNdeclared route is still flagged; add a policy-driven rule (a declared route is never judged by scanner path rules) unless a smaller safe rule exists; record the decision. Recall: `/.git`, `/.git-credentials`, `/.svn/entries`, `/.hg/dirstate`, `/.htpasswd`, `/.htaccess`, `/.npmrc`, `/.DS_Store`, `/id_rsa`, `/backup.sql`, `/backup2026.zip` flagged; `/.gitignore`, `/.github/`, `/docs/git-guide`, `/api/v1/sql-reports` clean (whole segments, root only for files that are legit deeper). Scanner UAs: `commix`, `netsparker`, `arachni`, `w3af`, `webinspect`, `havij`, `sqlninja`, `whatweb`, `detectify`, `jorgee`, `zmeu`, `paros`, `vega/`, `qualys was` as whole words; real browser UAs (the Task 0 UA list) stay clean.
- [ ] Harness scanner lists and UA benign list; corpus, gates, `make ci`, commits `fix(engine): never judge a declared route by scanner path rules` and `feat(detect): more scanner probe paths and user agents`, push each.

### Task 7: Zero-FP token rules (SQL time/exec, SSI)
**Files:** `internal/detect/sqlixss.go` or `injection.go` (where curated SQL tokens live), tests, corpus.
- [ ] Failing tests, hits: `WAITFOR DELAY '0:0:5'`, `;WAITFOR DELAY '0:0:5'`, `exec master..xp_cmdshell 'ipconfig /all'`, `xp_cmdshell`, `pg_sleep(5)`, `DBMS_LOCK.SLEEP(5)`, `<!--#exec cmd="ls" -->`, `<!--#include virtual="/etc/passwd" -->`, `<!--#echo var="DOCUMENT_URI" -->`, `<!--#printenv -->`; clean: `waiting for delay in shipping`, `delay: 5 days`, `sleep 5 minutes`, `<!-- comment -->`, `<!--# not ssi`-style prose without a directive name. Use whole-token matching and a bounded scan; report the benign hit counts from the harness (expected 0).
- [ ] Harness SQLi/SSI lists delta; corpus, gates, `make ci`, commit `feat(detect): flag waitfor delay, xp_cmdshell, pg_sleep and SSI directives`, push.

### Task 8: Corpus regression sets, docs, release alpha.6
**Files:** `testdata/corpus/*`, `docs/threat-model.md`, `CHANGELOG.md`, `README.md`, `adapters/fiberv2/README.md`, `adapters/fiberv2/go.mod`/`go.sum`.
- [ ] Add external benign FP groups and attack families not yet in the corpus (generic phrasing, no private data), regenerate, set gate constants to real counts. Update threat-model known gaps (what is fixed, what is still accepted, e.g. `x; sleep 10`, `bus.pass`), CHANGELOG, README counts and tables, corpus README. Full harness rerun with a comparison table vs `baseline-alpha5.md` saved next to the baseline (outside the repo). `uptime` load below ~10 then `make perf` and `make bench` best of 3, else "not re-measured". `make ci`, `make fuzz-quick` exit 0. Commit `docs: alpha.6 changelog, threat model and corpus counts`, push.
- [ ] Tag core `v0.1.0-alpha.6` and push the tag; in `adapters/fiberv2` run `GOWORK=off GOPROXY=direct go get github.com/ergasterion-dev/aegolith@v0.1.0-alpha.6`, hand-review go.mod/go.sum, update install notes, `go test -race -count=1 ./...`, commit `release: pin adapter to core v0.1.0-alpha.6, update install notes`, push, tag `adapters/fiberv2/v0.1.0-alpha.6`, push the tag.
- [ ] Verify from a clean empty scratch module (`GOWORK=off`, both at alpha.6, `go mod tidy` in the scratch module only): a main that blocks `please send 1 UNION SELECT password FROM users--` in enforce mode and references `fiberv2.New`. Report tags and SHAs.

QuickDrop bump, owner-resumed promote and prod-lab re-test are run by the controller after this plan, not by an implementer.
