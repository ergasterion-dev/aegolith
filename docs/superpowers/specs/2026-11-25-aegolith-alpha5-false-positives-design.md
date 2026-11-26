# Aegolith v0.1.0-alpha.5: false positives from external testing and G1b

Status: approved by the owner on 2026-11-25 ("go approved"). Short design.

## Intent
External testing of alpha.4 showed three things between alpha.4 and enforce readiness. Fix them; keep every gate.

## Goals
1. **CmdI one-word-prefix `sleep`.** `Mon; sleep 8` and `Gate 2; sleep 10` are flagged today (CMDI-001); the alpha.4 docs claimed they were not. Implement the documented behaviour: after a prose-like operator (a one-word prefix then `;`), `sleep N` is not enough on its own. A leading operator (`; sleep 10`, `| sleep 10 |`, `&& sleep 10`) stays caught. Choose the smallest change; keep `Passport; "id"`-style costs documented as before.
2. **SSTI `${a.b}` member access.** `${order.total}` is flagged (SSTI-001). Member access / calls inside `${...}` must be flagged only when the expression is attack-shaped: arithmetic (`${7*7}`), a call to a known dangerous root or method, or a member path whose segments include a sensitive name (for example password, passwd, secret, token, env, class, getClass, runtime, system, process, session). `${user.password}` must still hit. `${order.total}`, `${user.name}`, `${file.txt}`, `${amount(usd)}`-style benign shapes stay clean. Keep `${T(`, `${jndi:`-style lookup behaviour (JNDI rule) unchanged.
3. **G1b.** A base64 Java serialized object (`rO0AB...`) placed in an unknown route path only gets AEG-ROUTE-001, not AEG-CODEI-002 (the same payload is detected in query/JSON). Find why the path scan misses it (likely a prefilter or path-segment handling) and fix it without making a legit path match. The SQLi union on an unknown path already works.

## Non-goals
- The pre-existing libinjection false positive on `6-7 or 8` (not flagged in the external test run; needs its own investigation).
- Over-cap body cost (G8), uninspected headers, compressed bodies.

## Anti-goals / gates
Legit corpus stays at 0 false positives (now 118; add the new near-misses); attack gates stay at least 128/132 generic and 129/132 API-aware and may only rise; detectors stay linear; no private names in the public repo; `make perf` only on a quiet machine, otherwise say "not re-measured".

## Approaches
CmdI: (a) only suppress when the prefix is exactly one word and `sleep N` ends the value (chosen: smallest, matches the documented intent); (b) drop `sleep` entirely (loses `; sleep 10`). SSTI: (a) allow-list of benign shapes (rejected: unbounded), (b) flag member access only for sensitive names or calls (chosen). G1b: investigate; builder decides.

## Release
Tag core `v0.1.0-alpha.5`, pin adapter, tag adapter, clean-module verify; downstream rollout steps are tracked outside this repository.
