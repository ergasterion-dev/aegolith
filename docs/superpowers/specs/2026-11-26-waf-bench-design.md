# Design: Aegolith WAF bench

Status: approved 2026-11-26.

## Intent and why

Before a public open-source release we want evidence about Aegolith that the project did not write itself: how much it detects, what it wrongly flags, and what it costs under load. Today's corpus (230 attacks, 195 legitimate requests) was written by the team that tuned the rules, so growing it proves little. Readers of the published numbers must be able to reproduce them.

## Goals

1. Run independent attack sets against Aegolith over HTTP, in enforce mode locally, and report what was blocked and what got through.
2. Run a much larger body of legitimate traffic and report every false positive.
3. Run for hours under load and report latency, errors and memory growth.
4. Run the same tool against a remote deployment the operator owns, in monitor or enforce mode, with safety limits.
5. One command produces a dated report that can be compared with the previous one.

## Non-goals and anti-goals

- No new detectors or rule changes. Findings become issues for later releases.
- Not a general web scanner, and not a denial-of-service tool.
- No comparison claims against other WAFs in this version.
- Failure: numbers that look good only because rules were tuned on the test set, or because the same payload was counted many times.
- Failure: a remote run that changes data, reaches a third party, or hurts the target.

## Constraints

- The core module keeps its single dependency. The bench is its own Go module under `bench/`.
- Third-party test sets are fetched by a script at a pinned version, with checksum and licence recorded; they are not copied into the repository. A source whose licence does not allow this use is left out and listed.
- Payloads from third-party sets have outbound callback hosts rewritten to a reserved `.invalid` name before anything is sent.

## Approaches considered

| Approach | Gets | Costs |
|---|---|---|
| A. Local bench in the repository | Enforce mode, any volume, reproducible by anyone | Not real routes or a real network path |
| B. Same tool against a staging deployment | Real routes and journeys | Private results; needs a staging window |
| C. Same tool against production | Real network path and replicas | Risk to the service and its data |

Chosen: A, plus a remote mode (C) for a deployment the operator owns. B can reuse the same remote mode later. Details of any particular deployment are not kept in this repository.

## Parts

1. **Target server** (`bench/target`): a small HTTP API wrapped by the adapter, with the example route policy, switchable between enforce and monitor, and between "no policy" and "typed policy". It answers 200 to everything that reaches it, so a block is unambiguous. It exposes the decision and rule IDs for each request ID.
2. **Sources** (`bench/sources`): one importer per source, each converting to the existing corpus JSONL line format plus `source`, `source_case_id` and `expected` (attack or legitimate).
   - Existing project corpus (baseline).
   - OWASP Core Rule Set regression tests: stages that expect a rule to match are attacks. Stages that expect no match are often deliberate near-misses, so they are reported as a separate `near-miss` group and never enter the false positive rate.
   - GoTestWAF test cases, including its encoders and placeholders.
   - A large legitimate set: the project's legitimate cases, a generator of ordinary free text (names, addresses, reviews, prices, code-like and punctuation-heavy text, several languages), and a public benign HTTP set if one with a suitable licence exists.
3. **Held-out split**: each third-party case is assigned by an unsalted hash of its decoded payload to `dev` (may inform rule work) or `held-out` (30%; reported only in totals, individual cases never listed). The assignment therefore survives source version changes. It is a reporting discipline, not a secret, and the report says so. Published headline numbers use held-out.

   **Unit of counting**: one case is one distinct request after encoding and placement (payload x encoder x placeholder). Identical requests from different sources are merged and credited to each source, counted once in totals. The report also gives the number of distinct payloads detected in at least one placement and in all placements.
4. **Runner** (`bench/run`): two phases.
   - Detection: every unique case once, per policy configuration. Outcome per case: blocked, flagged, passed, or rejected before the WAF (malformed for the server). Detection rates count unique cases only.
   - Load: a mix of legitimate and attack traffic at a set rate and duration; records p50, p90, p99, errors and the target's memory. Load results never change detection numbers.
5. **Report** (`bench/report`): Markdown and JSON with aegolith commit, source versions, configuration, detection by source and category, false positive rate with every legitimate case flagged (dev split) listed, latency, and the difference from a previous report.
6. **Remote mode**: the runner pointed at another base URL. Off unless all of these are given: a target file naming the host, a matching `--confirm-host`, an allow-list of method and path pairs (payloads are placed only into those), and a rate ceiling. It sends no credentials unless the target file says so, tags every request ID with a fixed prefix, and stops on the first 5xx, failed health check, 403 on a benign control probe, or any other status the target file lists as a stop status. In enforce mode a 403 on an attack case is the expected block; any other answer to an attack case is recorded as passed. Outcomes come from a decision-log file the operator collects, joined by request ID. The allow-list governs every request, legitimate and load traffic included. Remote requests keep the allow-listed path exactly: payloads go only into query values, header values and bodies, never into the path, and the tool refuses a target file whose paths are not already in normalised form. Attack and legitimate cases that cannot be sent this way (path payloads, other methods) are reported as not sent, never silently dropped. Per-case outcomes need both the target's access log (the request arrived) and its decision log (what was decided), joined by request ID; a request missing from the access log is `unknown`, not `passed`. Route-level decisions (unknown route) are counted apart from content detections. The runner also stops if an operator-supplied stop file appears, or if that watcher's heartbeat file is older than 30 seconds.

## Success

- `make bench-waf` runs the detection phase locally from a clean checkout and writes a report.
- The report states detection and false positive rates per source, with held-out totals.
- A one-hour load run completes with a latency and memory record.
- A remote run refuses to start without its safety settings, shown by tests.

## Left to the builder

Package layout inside `bench/`, report layout, concurrency model, generator wording, and how decision IDs are exposed by the target.
