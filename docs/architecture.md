# Architecture

Aegolith is a library, not a proxy. A host API builds a `Firewall` once at startup and calls `Inspect` on every request, through the `net/http` or Fiber v2 middleware. This page describes how the code is organised and why. For what it does and does not stop, read the [threat model](threat-model.md).

## Packages

```
aegolith.go, config.go   Public API: New, (*Firewall).Inspect, Config, LoadConfig, type aliases
internal/model/          Action, Mode, Severity, Location, Category, Match, Decision, Request, Limits, Redact
internal/normalize/      percent-decoding (and double-encoding detection), JSON walker, query / form / cookie
                         parsing, multipart parsing
internal/protocol/       method, content type, body size, CR/LF/NUL, traversal, smuggling, double encoding
internal/detect/         attack detectors, the ScanText prefilter, scanner user agents and probe paths
internal/policy/         route table (trie matcher) and typed field validation
internal/engine/         the pipeline: wires everything, owns the scan budget, exclusions, modes, decisions
httpwaf/                 net/http middleware and the slog decision hook
adapters/fiberv2/        Fiber v2 middleware (a separate Go module)
testdata/corpus/         the attack and legitimate request corpus
```

Only `aegolith`, `httpwaf` and `adapters/fiberv2` are importable; everything else is `internal/`, so detectors can change without breaking users. `Request`, `Decision`, `Match`, `Route`, `Field` and the enums are type aliases re-exported from the root package.

### Dependencies

The core module depends on the standard library and `github.com/corazawaf/libinjection-go` (BSD-3-Clause) only. Fiber and fasthttp live in `adapters/fiberv2`, which has its own `go.mod`, so a `net/http` user never downloads them. Adding any other dependency to the core needs a written justification in this file in the same change.

## The pipeline

`Engine.Inspect` runs these steps. Cheap checks come first. In enforce mode the first match whose action is `block` stops the rest of the work.

```
 Request
    |
    v
 1. canonicalize header keys; decode the path once; match the route on the RAW path
    |
    v
 2. protocol        method, content type (only with a body), body size, CR/LF/NUL, traversal,
    |               Transfer-Encoding / Content-Length, double-encoded path
    v
 3. probe path + User-Agent    scanner rules
    |
    v
 4. route           unknown route (monitor by default); path params: typed values are validated,
    |               undeclared ones scanned
    v
 5. query           key rules (NoSQL operators, session ids), then each value: typed, or scanned
    |
    v
 6. body            by media type: JSON walk, form, multipart (file parts skipped), XML (XXE rule
    |               only if allowed), text/*; other types are not scanned
    v
 7. cookies, then User-Agent / Referer / configured headers
    |
    v
 8. rule actions -> exclusions -> de-duplication (rule + field) -> mode -> Decision
```

Rule-action overrides and exclusions are applied as each match is added (`state.add`), so an excluded match never stops the pipeline. The mode is applied last: `enforce` blocks when any remaining match has action `block`; `monitor` allows, sets `Decision.Monitored` and keeps the matches.

### Typed validation

A route declares path parameters, query values and body fields with a type: `uuid`, `int`, `number`, `bool`, `enum`, `string`, `text`, `email`, `phone`, `url`. A value that fails its type is `AEG-SCHEMA-001` (block). A value that passes a **fully constrained** type (`uuid`, `int`, `number`, `bool`, `enum`, `phone`) is not scanned: it cannot carry an injection. `string`, `text` and `email` are validated and then still scanned; `url` also gets the SSRF rules. Undeclared fields on a route that declares a map for that location are `AEG-SCHEMA-002` (monitor by default) and are scanned. This is where the speed comes from: most fields in a JSON API have a known shape.

Routes are matched on the **raw** (escaped) path, then each parameter is decoded. Matching on the decoded path would let `%2F` split or forge a segment. A literal segment sent percent-encoded does not match its route, so the request is treated as an unknown route and every input is untyped, which only adds inspection. Literal segments are compared case-sensitively unless `case_insensitive_routes` is set or the adapter marks the request (`Request.CaseInsensitiveRoutes`, which the Fiber adapter sets when Fiber routes case-insensitively); then they are compared after ASCII lower-casing, the most specific template wins as usual (literal, then parameter, then `*`), templates that differ only in letter case resolve to the first declared, and parameter values keep their case. An unmatched variant still gets every detector but loses the route's typed fields and `unknown_fields` action (see the [threat model](threat-model.md#routes-aegolith-does-not-match)).

### Detectors

`detect.ScanText` runs the text detectors in a fixed order: SQLi, XSS, CmdI, CodeI, LDAP, SSTI, JNDI, CRLF, LFI, RFI, SSRF. A prefilter (`mayContainAttack`) skips all but SQLi when a value has none of the bytes and markers the others need, which is most real customer text. SQLi always runs because a quote-free injection such as `1 OR 1` is made of words only, and libinjection decides that, not a copy of its dictionary here. Every detector checks the value and, when one percent-decoding pass changes it, the decoded value. Every detector is linear in the length of the value.

SQLi and XSS use libinjection. The rest are hand-written scans that need a structural signal (an operator plus a command, a closed template expression, a filter breaker), never a bare English word. A few rules take keys rather than values (`JSONKey`, `QueryKey`, `Session`), and `UserAgent` and `ProbePath` take the User-Agent and the path.

### Scan budget and windowing

Two design decisions keep the cost of an adversarial request bounded:

- **Windows.** A value up to `MaxValueLen` (default 8 KiB) is one window, so ordinary values cost exactly one scan. A longer value raises `AEG-PROTO-011` (monitor) and is scanned in windows of `MaxValueLen` bytes that start every `MaxValueLen/2`. Every byte is scanned at most twice, and an attack shorter than half a window always lies wholly inside one window, so padding cannot push it out of sight. Config rounds `MaxValueLen` down to an even number so the step is exactly half.
- **Budget.** Every window is charged its length against a per-request budget of `8 * (MaxBodyBytes + 256 KiB) + 64 KiB`. The first window that does not fit raises `AEG-PROTO-011` once and stops all further scanning in that request. The factor 8 comes from the worst case for a body byte: a walked JSON string can be 3 times as long as its source (each invalid UTF-8 byte becomes U+FFFD), the windows double that, and a raw rescan after malformed JSON adds 2 more. Exhausting the budget is a documented gap, not a crash; see the [threat model](threat-model.md#resource-bounds).

Matches are always charged by bytes actually scanned, JSON is walked without building a tree, and JSON path strings are rebuilt only when they change.

## Decisions are deterministic

For a given `Config` and request the `Decision` is the same every time, except `Decision.Duration`, which is the measured inspection time. There is no global mutable state; a `Firewall` is immutable and safe for concurrent use. Where Go would otherwise leak map order (headers, path parameters), the code sorts keys first, so the reported match does not depend on iteration order.

## No panic, fail open by default

`Inspect` recovers from any panic and returns a `Decision` with `Err` set and an action from `FailOpen` (allow by default, block when `fail_open` is false). The adapters add a second recover around building the request, and around your hook and block handler. An availability bug in a security layer must not take the API down, so the default is to let the request through and tell the hook. See the fail-open discussion in the [threat model](threat-model.md#fail-open-trade-off).

Match snippets are redacted (`model.Redact`: at most 64 bytes, control and format characters replaced) and field names are cleaned and capped at 256 bytes (`model.SafeName`). Full values are never logged.

## Configuration

`Config` is validated in `New` and failures are reported at startup: unknown route fields, field types, actions, rule selectors, exclusions and limits. `LoadConfig` reads the same structure from JSON and rejects unknown keys and trailing data. A `Firewall` keeps its own copy of everything in the config.

Rule selectors (in `rule_actions` and exclusions) are an exact ID (`AEG-SQLI-001`), an ID prefix ending in `*` (`AEG-SQLI-*`, or `*`), or a category name (`sqli`). An exact ID beats the longest prefix, which beats the category.

## Adapters

`httpwaf.Middleware` and `fiberv2.New` do the same job: build an `aegolith.Request` (copying everything out of fasthttp, whose buffers are reused), read at most `MaxBodyBytes + 1` bytes of the body and give the handler the complete stream back, call `Inspect`, call the hook for blocked, monitored or errored decisions, and on a block answer `403` with `{"error":"request blocked","request_id":"..."}`. The response names no product and no rule, so a probing client learns nothing about the firewall. Both adapters can be given a custom block handler.

Route matching is always Aegolith's own: Fiber v2 global middleware cannot see the matched route, so the adapters pass method and path only.

## Why no CRS

Running the OWASP Core Rule Set on every request costs 1 to 2 ms of CPU per request or more in every engine the project measured (see the [README](../README.md#why)), and the rules are generic regexes that give false positives on ordinary JSON. Aegolith instead exploits what an API knows: most fields have a known shape and a value that matches its shape cannot carry an injection, so heavy detection runs only on free text. The detectors are small, linear, and tested against a corpus of both attacks and legitimate traffic. CRS is used as a reference for some patterns (Apache-2.0, with attribution in [NOTICE](../NOTICE)); there is no SecLang parser and no CRS compatibility. A Coraza-backed engine for a few risky routes is on the roadmap.

## How to add a detector and a corpus case

1. **Write the failing test first.** In `internal/detect/*_test.go`, add true positives and, next to them, the false-positive shapes the rule must not touch (prose with `&`, `;`, `#`, `<`, `%`, non-Latin text, names with apostrophes). A detector without negatives will not be merged.
2. **Add the detector** in `internal/detect` as a pure function of one value: `func(v string) (Hit, bool)`, linear in `len(v)`, no globals. Use `valueOrDecoded` to check the decoded form too. Pick the next free rule ID `AEG-<CATEGORY>-<NNN>` and a severity. Never reuse or renumber an ID.
3. **Register it.** Text detectors go in the `textDetectors` list in `scan.go`, and the `mayContainAttack` prefilter must let through every byte or marker the detector needs; `TestScanTextPrefilterSafe` and `TestScanTextPrefilterSound` catch a miss. Key and path rules are called from `internal/engine/inputs.go`. A new category goes in `internal/model` and is re-exported in `aegolith.go`.
4. **Add the rule to the README rule table** and, if it has a known gap, to the [threat model](threat-model.md).
5. **Add corpus cases.** Append attack lines to `testdata/corpus/attacks.jsonl` (via `source/attacks.sh` and `gen.sh` for the generated ones) and legitimate lines to `testdata/corpus/legit.extra.jsonl`, then run `sh testdata/corpus/gen.sh`. The format is described in [`testdata/corpus/README.md`](../testdata/corpus/README.md). Update the gate constants in `corpus_test.go` only if the totals change.
6. **Run `make ci`** and, for anything that touches a hot path, `make bench` before and after.

A false positive reported by a user follows the same path in reverse: add the shape to `legit.extra.jsonl` first, watch it fail, then narrow the rule.
