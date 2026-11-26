# Aegolith v0.1.0-alpha.6: false positives and cheap recall from external validation

Status: owner decisions recorded 2026-11-25 ("fix all known false positives, accept some recall cost"). Short design.

## Intent
An independent validation of alpha.5 (34,791 public attack records, 167,129 benign values) found real-customer false positives and several cheap recall gaps. alpha.6 fixes every known false positive and the zero-risk recall gaps, keeping every corpus gate. Prod stays in monitor mode; nothing here approves enforce.

## Goals
False positives (all must be fixed, each with an attack counter-case so recall of the real attack is kept where possible):
1. SQLi: product text `Word N% (word)` (`Sale 20% (today only)`, `Cotton 95% (organic)`, `80% ACRYLIC AND 20% WOOL`) and a bare `6-7 or 8` (libinjection `1&1`). Real SQLi such as `1 or 1=1`, `1' or '1'='1`, `1 UNION SELECT ...` stays caught.
2. CmdI: the locale token `; id;` / `; id)` inside a browser User-Agent comment; `Tea & cat -cozy /club`; a markdown single-backtick span in prose (`Use \`ls\` to list files`); a newline followed by a bare command in a query value. Decide and document `x; sleep 10` (accept the miss, or find a safe rule).
3. XSS: `javascript: yes=no; maybe (later)`; an HTML comment containing a backtick. A tag with `on*=`, `<script`, or `javascript:` URL in a real attribute stays caught.
4. SSTI: `{{ a|b }}` pipes (`{{ price | currency }}`, tldr `{{[-c|--check]}}`), `${t('cart.title')}`, `${bus.pass}`; make `#{}` consistent with `${}`.
5. SCANNER: a customer route named `.../actuator/<health|info|metrics|env>` must not be blocked when the route is declared in policy (decide the smallest safe rule; policy-driven allow of declared routes is preferred over weakening the scanner list).

Recall (only zero- or near-zero-FP rules):
6. CmdI: `$(...)`, `$((...))` and `echo` probes after an operator (commix default), gated so code-like benign text still passes within the documented trade.
7. SQLi tokens: `waitfor delay '`, `xp_cmdshell`, `pg_sleep(`, `dbms_lock.sleep(`; SSI `<!--#(exec|include|echo|printenv|config|set)`.
8. Scanner: secret/VCS files at the root (`/.git`, `/.svn/`, `/.htpasswd`, `/.npmrc`, `/.DS_Store`, `/id_rsa`, root `*.sql`, backup archives; whole segments, `.gitignore` stays clear); scanner user agents (`commix`, `netsparker`, `arachni`, `w3af`, `webinspect`, `havij`, `sqlninja`, `whatweb`, `detectify`, `jorgee`, `zmeu`, `paros`, `vega/`, `qualys was`).

## Non-goals
Broad absolute-path LFI, loopback URLs in prose, CRS function-name signatures, IE-only event handlers, SSRF NFKC (alpha.7 candidates), compressed bodies, headers beyond what is scanned today.

## Gates
- Legit corpus stays at 0 false positives (now 130); every FP above and every external benign group goes into `testdata/corpus/legit.jsonl` as generic phrasing (no private data).
- Attack gates (now 133/137 generic, 134/137 API) may only rise; set the constants to the real counts after `sh testdata/corpus/gen.sh`.
- External validation harness rerun before and after each detector task: per-category recall must not drop silently; natural-text FP rate (baseline 0.31%) must go down.
- Detectors linear and bounded; `make perf` only on a quiet machine, else "not re-measured".

## Release
Docs commit, tag core `v0.1.0-alpha.6`, pin adapter, tag adapter, clean-module verify; downstream rollout steps are tracked outside this repository. Never enable enforce.
