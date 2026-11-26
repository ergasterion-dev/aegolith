# Aegolith v0.1.0-alpha.4: detector gaps design

Status: approved by the owner on 2026-11-25. Short design (small, well-bounded change set).

## Intent

A downstream monitor-mode trial and an external attack matrix found detector gaps (G1-G8). Fix them so that SQLI-001 and the other text rules can be relied on in enforce mode. The owner decides when to enforce; this release only closes the gaps.

## Goals

- G1 (also G1b unknown-path scan, G1c long-value padding): SQL injection preceded by plain words and no quote is detected, e.g. `please send 1 UNION SELECT password FROM users--`, `milk 1; DROP TABLE orders;--`, and the same after 20k characters of padding.
- G2: `<scr<script>ipt>alert(1)</script>` is flagged as XSS.
- G3: Go template actions (`{{printf "%v" .}}`, `{{ call .Func }}`, `{{define ...}}`) and EL expressions (`${7*7}`, `${user.password}`) are flagged as SSTI.
- G4: command injection variants `x%0aid`, `; sleep 10`, `;w'h'o'am'i`, `;c\at /et\c/pas\swd` are flagged.
- G5: scanner probe paths match under a path prefix (`/api/v1/.env`, `/api/v1/.git/config`, `/api/v1/actuator/env`).
- G6: User-Agents of ffuf (`Fuzz Faster U Fool`), Wfuzz, feroxbuster, Hydra are flagged.
- G7: injection and prototype-pollution text in key names (JSON key, query key, `__proto__[x]` in a query) is flagged.
- G8 (adapter): in monitor, a body larger than the cap is still inspected up to the engine's documented limit, and a cap-truncated body does not raise PROTO-020.

## Non-goals

- G9 items (MySQL-only syntax, fullwidth/`%u`/overlong encodings, nip.io SSRF, XPath, Python `__import__`): documented as known, not fixed.
- No new rule categories beyond what each gap needs; no generic CRS-style rule sets.
- No change to enforce/monitor semantics or severities.

## Anti-goals

- Any new false positive on the legit corpus (0/91 stays 0/91) or on the known prose near-misses in the threat model.
- Dropping the attack gates (103/107 generic, 104/107 API-aware).
- Breaking the latency budget (p99 under 50 us; last measured 10-21 us) or linearity of the scan.
- Any private product name, host or infra detail in the public repo.

## Approaches considered (G1, the hard one)

1. **Rescan from every word start.** Simple, catches the most, but risks flagging prose (`please union select the best`) and costs O(words) libinjection calls.
2. **Rescan from bounded extra start offsets chosen at SQL-keyword / number tokens (chosen).** libinjection already detects the attack when it begins at the digit or keyword; the leading words are what defeat it. Starting only where a keyword or number begins keeps cost small and false-positive exposure low. Cap the number of starts per value (linear total). Each candidate suffix still has to pass libinjection's fingerprint, and the prose guards (`isProseNumberComment`) apply.
3. **Reimplement a SQL tokenizer.** Rejected: large, risky, and contradicts relying on libinjection's dictionary.

Padding (G1c) needs no separate mechanism: the existing overlapping windows already contain the payload; the fix applies per window.

## Constraints and decisions

- Work test-first: each external test payload is added to `testdata/corpus/attacks.jsonl` (or the matching unit test) as a failing case, paired with legit near-miss prose in `legit.jsonl` / unit tests that must stay clean.
- Other gaps (G2-G7) are small, local changes in `internal/detect` and `internal/engine`; G8 is in `adapters/fiberv2`.
- Update `docs/threat-model.md`, `CHANGELOG.md`, README numbers (from real runs; `make perf` only on a quiet machine, load below ~10).
- Release order: tag core `v0.1.0-alpha.4`, pin adapter to it (no `replace`), tag `adapters/fiberv2/v0.1.0-alpha.4`, verify from a clean scratch module.

## Left to the builder

Exact start-offset selection and cap for G1, the keyword list used to pick starts, exact token lists for G3/G4/G6, and the shape of key-name scanning in G7 (rules reused vs new rule IDs), provided every gate above holds.
