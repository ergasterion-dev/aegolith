# Aegolith WAF bench

The bench sends sets of requests over HTTP to a server wrapped in Aegolith and counts what the firewall did with each. It also measures that server under load, and can send a filtered subset of the requests to a deployment you own. It is a Go module of its own (`bench/`, command `aegobench`), builds against the library in the parent directory and is part of no release.

The [first report](../docs/bench/2026-11-first-report.md) is in `docs/bench/`. The [design](../docs/superpowers/specs/2026-11-26-waf-bench-design.md) is in the repository.

## One command

From the repository root:

```sh
make bench-waf                              # detection: writes bench/out/report.md and report.json
make bench-load DURATION=1h RPS=2000        # load: writes bench/out/load/report.md and report.json
```

You need Go 1.25 or later, bash, git and, to fetch the third-party sets, jq and network access to github.com. Both targets run [`scripts/run-local.sh`](scripts/run-local.sh), which

1. builds `aegobench` with the commit recorded in it (the report says when the tree had uncommitted changes, and "unknown" for a tree without git history),
2. fetches the two pinned third-party sets into `bench/.sources/`, running nothing it fetches,
3. imports the sources into `out/cases/`,
4. starts a target on a free loopback port and runs against it. `bench-waf` does this twice, without a policy and with [`testdata/corpus/example-api-policy.json`](../testdata/corpus/example-api-policy.json), each time with a fresh target and fresh logs under `out/runs/`. `bench-load` starts one enforce target and writes into `out/load/`,
5. writes the report, with the machine, the tool versions and the load average before and after the runs. The report is written to hold no host name, user name or local path.

It stops only the processes it started, by process ID, also when it fails or is interrupted. It removes an earlier report from the output directory before it starts. `make bench-waf` exits non-zero if any case has the outcome unknown; the report is still written, but such a run should not be published.

Settings are environment variables (`SOURCES=baseline make bench-waf` runs only the project corpus and fetches no test set; Go itself still downloads the modules the bench needs if they are not in its module cache): `SOURCES`, `OUT`, `LEGIT_SEED` (1), `LEGIT_N` (5000), `DETECT_RPS` (500), `PREVIOUS` (an earlier `report.json` to compare with), and for load `DURATION` (1h), `RPS` (2000), `WORKERS` (64), `ATTACK_SHARE` (0.1), `LOAD_SEED` (1) and `POLICY` (none). The script's header lists them.

## Reading a report

**Outcomes.** One case is one distinct request.

| Outcome | Meaning |
|---|---|
| blocked | the firewall blocked the request |
| flagged | allowed, although a rule other than a route rule matched without blocking: a rule whose action is `monitor` (in enforce mode too), or any rule in monitor mode. It counts as detected, and so as a false positive on a legitimate request |
| route-only | allowed, and only route rules (`AEG-ROUTE-*`) matched; not counted as a detection |
| passed | reached the application with nothing decided about it |
| rejected | the server answered before the firewall saw the request; in no rate |
| unknown | the answer and the logs do not say what happened; in no rate |
| not-sent | the client cannot send the case as given (the report gives the reasons); in no rate |

**What was detected.** A detection need not mean that an attack was recognised. The report splits every detection, of attacks and of legitimate requests alike, by the rules that matched, under the headline rates and in the tables of totals, sources, categories, encoders and placements:

| Part | Meaning |
|---|---|
| content rule | at least one rule that looks for an attack in what the request says (`AEG-SQLI-*`, `AEG-XSS-*`, `AEG-CMDI-*` and the other attack families) |
| protocol rules only | only `AEG-PROTO-*` matched: the method, content type, body size, control characters, raw path or transfer encoding, an inspection limit or a body that cannot be parsed |
| schema rules only | only `AEG-SCHEMA-*`: a declared field that fails its declaration (its type, length, range, enum values or pattern), or a field that is not declared |
| scanner rules only | only `AEG-SCANNER-*`: a scanner's `User-Agent`, or a probe or backup path |
| anything else | more than one of the last three, a block by a route rule alone, or a block without a rule |

Route rules are left out of this split, except that a block by them alone is "anything else". Read the content rule figures beside the detection rate. With the pinned sets, most of the protocol-only detections are `AEG-PROTO-002`, the refusal of a body whose content type is not allowed: by default only JSON, form and multipart bodies are, so XML and text bodies are refused. **A deployment that allows more content types would lose those blocks.** In enforce mode the first blocking match ends the inspection, and the protocol checks, then the scanner checks of `User-Agent` and of probe and backup paths, come before any value is read: a refused body was never read, and the bench does not measure what the content rules would find in a request blocked by protocol or scanner rules only. Once a type is allowed, the content rules read `text/*` bodies, and XML bodies under `allow_xml`; besides JSON (including `+json` types), form and multipart, a body of any other allowed type is read by none of them. The report counts the rules behind the protocol-only detections.

**Encoders, placements and headers.** The report also counts results by source and encoder, and by source and placement (where the importer says the payload is). Aegolith does not decode base64, so a payload that a source sends in base64 is read as the encoded text; the report says what share of GoTestWAF's attack lines are sent that way. By default the values of `User-Agent` and `Referer` (SSRF results there are ignored) and of the cookies are scanned, and a scanner rule judges `User-Agent`; any other header's value is scanned only if the configuration lists it in `inspect_headers`, as the example policy does with `X-Api-Version`. Protocol rules check every header for CR, LF and NUL, and check `Content-Type` and `Transfer-Encoding`.

**Held-out and development sets.** A case from any source but the project's own corpus (`baseline`), **the generated traffic included**, is *held out* if, for any of its decoded payloads, the first 8 bytes of the payload's SHA-256 are read as a number and the number taken modulo 100 is below 30: a fixed 30%, unsalted. A case without a payload is assigned by the same test on its case ID. All others are the *development* set; cases only `baseline` provides are in neither. **Headline numbers use the held-out set.** This is a reporting discipline, not a secret: anyone can compute which cases are held out, and the case files, results and logs of a run name them. The rule is that detectors are not tuned on held-out cases and held-out cases are not looked at one by one; the report counts them and never lists them.

**False positives.** Read them by source and category. The total depends on the mix of legitimate requests: in the generated set, punctuation-heavy prose and pasted code are 25% of the lines by choice, and text in other languages is 10%. Near-miss requests resemble attacks without being expected to be detected; they are counted apart and enter no detection or false positive rate.

**The example policy** describes a small sample API. The project's own corpus is written for it; the third-party sets and the generated traffic are not. A request to a path it does not declare matches the unknown-route rule, which is why most cases that are not blocked are route-only in that configuration. One generated endpoint, `POST /api/v1/cart/items`, is declared by the policy as a route that blocks undeclared fields, and the generator sends it the fields `sku` and `comment`, which the policy does not declare. Those requests are blocked and count as false positives of that configuration.

## Sources

The third-party sets are pinned by commit in [`sources.json`](sources.json): the OWASP Core Rule Set regression tests (v4.31.0, Apache-2.0) and GoTestWAF (v0.5.11, MIT). These are the versions that were pinned when the importers were written; they are not claimed to be the latest. Their trees are fetched as test input, are not redistributed and are treated as untrusted data.

**What "attack" means differs by source.**

- **CRS:** a test that requires the rule set to log at least one rule ID. That includes rules of every paranoia level up to 4, because the importer does not filter by level, and protocol checks, such as a test that expects a request without an `Accept` header to be flagged (in release v4.31.0, 553 of the 5,054 imported lines, attack and near-miss together, are category `protocol`). A test that only forbids rule IDs is near-miss. A test file belongs to one rule and each imported test is one request, written to check what the rule set logs for it: the request need not be a working exploit, and some hold only a fragment of an attack, such as a bare function or class name.
- **CRS payloads** are identified by a heuristic. In v4.31.0, 1,762 of the 5,054 lines have no identifiable payload and are split into held-out and development by case ID. Such a case has no stable set across source versions.
- **GoTestWAF:** one case per payload, encoder and placeholder. A test set whose name holds `false` is legitimate; everything else is an attack. Some of the encoders are base64, which the firewall does not decode.
- **Conflicts:** requests whose sources, or lines of one source, disagree on what to expect are left out, and the report counts them.

**How the requests differ from the tools' own.** The CRS importer reproduces what go-ftw v2.3.0, the runner the pinned tree uses, sends; it was read from that version's source. Headers are sent in canonical case and in the sender's order, `X-Request-Id` is added, and stages the sender cannot reproduce are skipped and counted by reason. The details are in the package comments of [`internal/sources/crs`](internal/sources/crs/crs.go) and [`internal/sources/gotestwaf`](internal/sources/gotestwaf/gotestwaf.go).

**Callback hosts** in CRS and GoTestWAF requests are rewritten to `callback.invalid`, to make it less likely that a request sent later makes a server contact a public host. The rewriter is best effort: it reads hosts in `scheme://host` URLs, protocol-relative `//host.tld` forms and JNDI lookups, through many encodings, and is not a parser of every URL dialect, a shell or a language emulator. Examples of what it leaves alone, by design or as known limits (not a complete list): a host outside a URL (a bare name or address in a command or header, a mail address); after `//` without a scheme, in `file:` URLs and with fewer than two slashes, a single label, an address shorter than four parts and a name ending like a file; the authority of `php:`, `data:`, `phar:`, `javascript:` and similar URLs; an IPv6 address without brackets; anything inside base64, more than ten layers of encoding or an encoding it does not know, including overlong UTF-8; and some hosts after unusual user info. `RewriteCallbacks` in [`internal/cases/callback.go`](internal/cases/callback.go) describes what it reads. What protects a run is where the bench sends: only to loopback, or in remote mode only to your allow-list, and whatever you control on the target side, such as the egress your target's network allows. The XML namespaces of GoTestWAF's SOAP envelope are sent as they are.

## Generated legitimate traffic

There is no public set of real legitimate traffic here: two candidates are listed in `sources.json` and left out because their licence or terms were not verified. Instead, `generated-legit` is built from this repository's templates and word lists, from a seed.

- **It cannot prove a real-world false positive rate.** The material is 321 templates and 4,166 entries in word lists; seed 1 with 5,000 lines uses all 321 templates and 3,575 of the entries. The 5,000 lines are combinations of these, not 5,000 independent trials: lines share templates and snippets, so one snippet that trips a rule can account for several blocked lines. The report counts, for pasted code, the distinct *core snippets* (the entries of the 16 word lists that hold the pasted text itself).
- The mix of categories is a fixed schedule, not a model of real traffic.
- **Near-miss rule:** a text with the canonical shape of an attack (a script element, an `on...=` event handler attribute, a `javascript:` URL, a command that reads `/etc/passwd` or `/etc/shadow`, a SQL time-delay call) is near-miss, not legitimate, however plausible a harmless sender is, and is reported as its own group. The rule was written after one replay of an earlier version of the set had been seen. It looks at the content alone and applies to every entry of these kinds.
- Text in languages other than English had no native review.
- Loopback and private IP addresses are absent (the name `localhost` occurs); real messages hold them.

## Logs, results and privacy

- Results, case files and the target's logs identify cases, **held-out ones included**: a request ID is a prefix and the case ID. Only the report keeps held-out cases to counts.
- The access log records the request ID, the method, the escaped path, cut at 256 bytes, and the time, so a payload sent in a path is in it. The decision log records the request ID, the action, whether the request was only monitored, the rule IDs, the template of the matched route, the firewall's decision latency and, for a failed inspection, its error text. Neither holds a query string, a body or a header other than the request ID.
- One run per log file: `detect` joins by request ID, so the logs it reads must hold that run alone. A target empties its logs when it starts.
- Go's `net/http` trims blanks at the edges of header values, and answers some malformed requests (400, 414, 417, 431, 501) before any handler runs. Those cases are *rejected* and say nothing about the firewall.

## Load results

`load` sends at fixed times whatever the target does: a request that is due while all workers are busy is dropped and counted, never queued, so a slow target shows as dropped requests and a lower sending rate. It does not send a case's own `Connection` header, uses no near-miss cases and writes no detection results.

- The generator and the target run on **one machine** and share its processors, so the numbers describe that machine at that moment.
- The client round trip includes HTTP handling on both sides and the connection.
- The **firewall decision latency** is read from the decision log, and covers only requests that left a decision record: those the firewall blocked, matched in monitor or failed to inspect. In enforce mode without a policy that is mostly the blocked requests; with a policy it also holds the requests that only monitor rules, such as the unknown-route rule, matched. It is **not** the firewall's overhead on all traffic. For per-request cost see [Performance](../README.md#performance).

## Remote mode

`remote` sends cases to a deployment **you own**. It is the only command that sends to a host other than loopback.

1. Copy [`target.example.json`](target.example.json) and describe your deployment: `base_url` (https, or http to a loopback host), `mode`, `max_rps`, `health_path`, `stop_statuses`, `headers` sent with every request (keep a file with credentials out of version control), and `allow`, the list of method and path pairs with the query, header and JSON placements that payloads may go into, and the statuses (2xx or 4xx other than 403) a harmless control request may get.
   **Attack payloads are sent to every allowed route, so a route that stores what it is sent or changes state will store attack payloads or change state.** That is why only `GET` and `HEAD` routes are allowed as they are: an entry with any other method is refused unless it sets `"may_write_data": true`, by which you accept that every request to it, attack payloads included, may be stored or change data on your deployment. The example file allows two `GET` routes and nothing else. Even a `GET` route can write, if your application does so on `GET`; allow only routes you know do not.
2. Your deployment must write the two logs in the bench's formats (JSON lines; see [`internal/records`](internal/records/records.go)), keyed by the `X-Request-Id` the bench sends. The access log must record the controls and health checks too; the decision log must hold what the firewall decided about the run's requests.
3. Send, collect the logs, join and report:

```sh
cd bench
go run ./cmd/aegobench remote --target out/my-target.json --confirm-host waf.example.test --rps 2 \
  --cases out/cases/crs.jsonl,out/cases/gotestwaf.jsonl --out out/remote/sent.jsonl --out-cases out/remote/cases.jsonl \
  --stop-file out/remote/stop
go run ./cmd/aegobench join --results out/remote/sent.jsonl --access out/remote/access.jsonl \
  --decisions out/remote/decisions.jsonl --out out/remote/results.jsonl
go run ./cmd/aegobench report --cases out/remote/cases.jsonl --results remote=out/remote/results.jsonl \
  --sources sources.json --out out/remote/report
```

**What it refuses and when it stops.**

- `--rps` is required and at most `max_rps`; `--limit` (default 200) bounds the case requests sent. `--confirm-host` must repeat the host of `base_url` exactly.
- Only a payload is taken from a case: it is placed at an allowed method and path. No header, path or other part of the case is sent. Redirects are not followed.
- Neither `headers` nor a header placement may name a framing, hop-by-hop or routing header (`Host`, `Connection`, `Keep-Alive`, `Proxy-Connection`, `Via`, `Max-Forwards`, `Forwarded`, `X-Host`, the client address headers such as `X-Real-IP`, and every name that starts `X-Forwarded-` or `X-Original-`, among others), a method override (`X-HTTP-Method-Override` and its kin) or `X-Request-Id`. A query or JSON placement may not be named `_method` or another name frameworks read as a method override.
- `health_path` is checked with GET only and is the one request outside the allow-list. The headers of the target file go with every request.
- Every allowed route first gets a harmless control request, repeated after every 50 cases sent to that route and after its last; health is checked at the start and then every 5 seconds.
- The run stops on any 5xx, a status in `stop_statuses`, a failed health check, a control answered outside its `benign_status`, three requests in a row ending in a redirect or no answer, the appearance of `--stop-file`, a `--heartbeat-file` that is missing, not a regular file, older than 30 seconds or more than 2 seconds in the future, or an interrupt. In enforce mode 403 is the expected block and may not be a stop status.

**What remote results mean.**

- **They cover a filtered subset, and their rates are not comparable with local rates.** A case is sent only if it has a payload, in a query, header or JSON placement for which your allow-list has a slot; form, path and other placements are not sent, and with the example target file, which has no JSON placement, neither are JSON ones. Cases not sent are listed in the results as not-sent with a reason.
- **A payload that could name a public host or address is never sent.** Like the callback rewriter, this check is best effort, not a shell or language emulator: a payload can assemble a host in ways it does not read, so what bounds a run is still your allow-list and what you control on the target side. Of the first report's case files, it refuses 599 of the 3,297 generated payloads in query, header or JSON placements (about 18%), among them 309 of 320 of the URL texts and 154 of 469 of the pasted code; a further 1,703 of the 5,000 generated cases have another placement.
- **A payload that could name a link-local address (`169.254.0.0/16`, `fe80::/10`) or a known cloud metadata address or name (such as `169.254.169.254`, `fd00:ec2::254`, `168.63.129.16`, `100.100.100.200` or `metadata.google.internal`) is never sent either**, in any of the notations the public-host check reads, with its own reason and no override. Of the first report's case files it refuses 32 of the 1,677 CRS payloads in those placements, and none of GoTestWAF's or the generated ones.
- **Loopback and private addresses (`127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16` and so on) are sent.** If a route you allow has a server-side request forgery bug, such a payload makes your server fetch that address inside its own network, from services that trust it. Allow only routes for which that is acceptable, or keep the cases that name such addresses out of the case files you give `remote`.
- `join` refuses logs that are not the run's: an access log that holds none of the run's controls and health checks, or, once cases were sent, a decision log with no record of the run's request-ID prefix and tag (an empty, misnamed or other replica's log, which would read every case as passed). Give `--allow-no-decisions` only if the firewall truly decided nothing about the run. It prints how many sent requests had an access record and how many a decision record.
- `join` never counts a request that is missing from the access log as passed: it is rejected if the answer was one of the statuses above (which a proxy in front of your service may also give) and unknown otherwise. `report` refuses results that were not joined.
- A request in the access log with no decision record reads as **passed** (as unknown if it was answered 403). In monitor mode a lost decision record therefore reads as passed. Beyond the checks above, `join` cannot tell whether your logs are complete: **a run whose decision log was sampled or incomplete must be reported as incomplete.**

## Commands by hand

`go run ./cmd/aegobench help` lists the commands; `go run ./cmd/aegobench <command> -h` lists the flags. From `bench/`, with the target in a second terminal:

```sh
go run ./cmd/aegobench import --source baseline --corpus ../testdata/corpus --out out/baseline.jsonl
./scripts/fetch-sources.sh
go run ./cmd/aegobench import --source crs --root .sources/crs --out out/crs.jsonl --skipped out/crs-skipped.jsonl
go run ./cmd/aegobench import --source gotestwaf --root .sources/gotestwaf --out out/gotestwaf.jsonl --skipped out/gotestwaf-skipped.jsonl
go run ./cmd/aegobench import --source generated-legit --seed 1 --n 5000 --out out/generated-legit.jsonl

go run ./cmd/aegobench target --mode enforce --access out/access.jsonl --decisions out/decisions.jsonl

go run ./cmd/aegobench detect --cases out/baseline.jsonl --base http://127.0.0.1:8088 \
  --access out/access.jsonl --decisions out/decisions.jsonl --out out/results.jsonl
go run ./cmd/aegobench report --cases out/baseline.jsonl --results no-policy=out/results.jsonl \
  --sources sources.json --out out/report
```

`target`, `detect` and `load` are for this machine: `detect` and `load` refuse any host but a loopback one. Tests: `go test ./...` in `bench/` (also part of `make test` at the root).
