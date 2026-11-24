# Threat model

Aegolith sits inside a Go JSON API and reads requests written by strangers. This document says what it is meant to stop, what it does not try to stop, and where it is known to be weak. It is deliberately blunt: a firewall library that overstates itself is worse than none.

It describes the code on `main`. Aegolith is pre-alpha; run it in monitor mode first.

Found a hole in any of this? Please report it privately: see [SECURITY.md](../SECURITY.md). A false positive or a missed attack that is not a security problem in Aegolith itself is a normal issue (use the templates).

## What Aegolith must never do

1. **Block a real customer.** A false positive is worse than a missed probe the backend would 404 anyway. Rules are tuned for the first and pay for it in recall (see [Known gaps](#known-gaps-and-trade-offs)).
2. **Add milliseconds.** The budget is tens of microseconds per typical request. A feature that costs more is off by default or out.
3. **Crash the host.** No panic escapes the middleware. An internal error follows `FailOpen`: allow by default, block if you turn it off.
4. **Log what it should not.** Snippets in a decision are redacted and at most 64 bytes; full request values are never logged.

## What it protects against

Aegolith inspects the request (method, path, query, headers it knows how to read, cookies and the body) and reports or blocks:

| Class | Rules | What it looks for |
|---|---|---|
| SQL injection, XSS | `AEG-SQLI-001`, `AEG-XSS-001` | libinjection on every free-text value, plus a check for stacked statements that copy to or from a program |
| OS command injection | `AEG-CMDI-001` | a shell operator followed by a command used as a shell is used, an absolute system path, reverse-shell and Shellshock markers |
| Code injection | `AEG-CODEI-001`, `-002` | PHP open tags, eval of base64, Node `child_process`, Java serialized objects |
| LDAP, template, JNDI, CRLF injection | `AEG-LDAP-001`, `AEG-SSTI-001`, `AEG-JNDI-001`, `AEG-CRLF-001` | filter breakers, code in template expressions, Log4Shell lookups (with nested obfuscation), header injection in values |
| File and URL abuse | `AEG-LFI-*`, `AEG-RFI-001`, `AEG-SSRF-*`, `AEG-XXE-001` | traversal and system files, wrapper schemes, metadata and internal hosts, DOCTYPE entities (only when XML is allowed) |
| NoSQL and prototype pollution | `AEG-NOSQL-*`, `AEG-PPOLL-001` | operator keys in JSON and query strings, `__proto__`, `constructor`, `prototype` |
| Reconnaissance | `AEG-SCANNER-*`, `AEG-SESSION-001` | scanner user agents, well-known probe paths and backup files, session ids in URLs |
| Protocol abuse | `AEG-PROTO-*` | methods, content types, CR/LF/NUL, encoded and double-encoded traversal, request-smuggling header combinations |
| Wrong shape | `AEG-SCHEMA-*`, `AEG-ROUTE-001` | with route policies: a value that does not match its declared type, an undeclared field, an unknown route |

Route policies make the strongest guarantee: a value that validates as a `uuid`, `int`, `number`, `bool`, `enum` or `phone` cannot carry an injection, so it is not scanned and cannot false-positive. The rule table in the [README](../README.md#rules) lists every rule and its default action.

## What it does not protect against

These are out of scope by design, not bugs. Put the right tool in front of or beside Aegolith.

- **Volumetric DDoS.** It runs in the application process after the connection is accepted. Use a network or edge service.
- **Rate abuse and credential stuffing.** There is no rate limiting, IP reputation or bot challenge.
- **Business-logic flaws.** Buying a negative quantity that the type allows, race conditions, price tampering the schema permits.
- **Authorization bugs.** Aegolith does not know who the caller is or what they may touch (IDOR, missing checks).
- **Attacks hidden in fields declared with the wrong type.** A field you declare `uuid` is trusted to be a UUID. If you declare a free-text field `string` or `enum` with a loose `pattern`, the guarantee is only as good as the declaration. A `string` field is still scanned (defence in depth), but a pattern such as `.*` buys nothing.
- **Response-side leaks.** Responses are never inspected.
- **Anything the backend does after decoding in a way Aegolith cannot see.** Aegolith inspects the bytes it is given. A handler that decodes the raw body itself (see Content-Encoding below) can see data Aegolith did not.
- **A compromised host or dependency.** It is a library in your process, not a sandbox.

### Fail-open trade-off

`FailOpen` defaults to true: if inspection hits an internal error, the request is allowed and `Decision.Err` is set. The reasoning is that an availability bug in a security layer must not take the API down. The cost is that anyone who can trigger an internal error can bypass inspection for that request. Set `fail_open` to false to invert it (blocked, 5xx-visible) if you prefer that risk. The decision hook is told either way; alert on `Err`.

## Who controls what

| Input | Controlled by | Trusted? |
|---|---|---|
| Method, path, query, headers, cookies, body | The client | No |
| `Config` (routes, exclusions, rule actions, limits) | The operator | Yes |
| The JSON config file | The operator | Yes (parsed strictly: unknown keys and trailing data are errors) |
| The decision hook and block handler | The operator | Yes |
| Rule IDs and rule logic | This repository | Yes |

## Resource bounds

A WAF library is itself a target for resource exhaustion. What is bounded, and what is not:

- **Per value:** a value longer than `MaxValueLen` (default 8 KiB, rounded down to an even number, minimum 2) is reported (`AEG-PROTO-011`, monitor) and scanned in overlapping windows that start every `MaxValueLen/2` bytes. Every byte is scanned at most twice, and an attack shorter than half a window always lies wholly inside one window, so padding cannot push it out of sight.
- **Per request:** every window is charged against a scan budget of `8 * (MaxBodyBytes + 256 KiB) + 64 KiB` bytes. The factor covers the worst expansion of a body (each invalid UTF-8 byte in a JSON string becomes U+FFFD, one byte to three, doubled by window overlap, plus a raw rescan after malformed JSON). A request whose body is within `MaxBodyBytes` and whose other inputs total at most 256 KiB cannot exhaust it.
- **Body:** at most `2 * MaxBodyBytes` of a body is inspected by the engine, and the adapters hand it `MaxBodyBytes + 1` bytes. A body over `MaxBodyBytes` raises `AEG-PROTO-003` (monitor).
- **Structure:** JSON depth (`MaxDepth`, default 32), field count (`MaxFields`, default 1,000: reported once as `AEG-PROTO-010`, the walk continues field by field under the budget), path length (key segments are capped at 256 bytes, whole paths at 4 KiB).
- **Detectors** are linear in the length of the value; the route matcher and the validators are linear; user `pattern`s run on Go's RE2 engine, so they cannot backtrack catastrophically.

The honest worst case: an adversarial 1 MiB body, for example repeated invalid UTF-8 plus `<`, can cost roughly 0.5 to 0.8 s of CPU and about 128 MB of allocation, about 93% of it inside libinjection-go. It is bounded, not cheap. Requests over `MaxBodyBytes`, or non-body inputs (URL and query, cookies, headers) over 256 KiB, can exhaust the budget; the engine then raises `AEG-PROTO-011` (monitor) and stops scanning, so the rest of that request is not inspected. Servers pre-empt most of the non-body case (net/http caps headers at 1 MiB by default, fasthttp uses small buffers).

Knobs: `limits.max_body_bytes`, `limits.max_value_len`, `limits.max_fields`, `limits.max_depth`. **Front the service with a body size limit** (a reverse proxy or `http.MaxBytesReader` / Fiber's `BodyLimit`) set to the largest request you accept. Aegolith's limits bound its own work; they are not a substitute for yours.

## Known gaps and trade-offs

Each item says what is missed and why. Most are the price of the first ground rule: never block a real customer. If one of these matters to you, say so in an issue; for several there is a stricter variant we could offer as an option.

### Recall traded for fewer false positives

- **Command injection after prose.** After a lone ` & ` in prose, or a two-word prose `; `, the CmdI detector does not flag some bare shapes: `x & id`, `x & ls`, `x & cat /flag` with no flag, `see you; id`, `see you; ls`, `see you; sh`, `; chmod +x` or `; chmod 755` with no file, and `| type /a`. They are indistinguishable from `Bring passport & id`, `dog & cat /dog-food`, `Notes; chmod 755` and `Pack of 2 | type /a`. A real flag after the ` & ` restores the full rules, and shell-only operators (`&&`, `|`, a backtick, `$(`) are always checked. Single-segment root paths (`/flag`) are not treated as paths in these positions.
- **Command injection false positives.** The same relaxation reads English-word "flags" after prose `&` as real ones, so a few harmless sentences are still blocked: `Delivery & ping -me 10.0.0.1`, `Tea & cat -lovers /club`, and the shape `Dog & cat /pet-food.html`. The corpus has none, but they are known.
- **XSS script URLs.** `javascript:` followed by `key=value; ...` is read as a statement and can false-positive on prose such as `javascript: a=1; b=2`, `JavaScript: yes=no; maybe`, `JavaScript: level=beginner (2 weeks)` and `javascript: name=Ali`. Entity-encoded whitespace inside a script URL (`javascript:&#9;location=name`) is missed. libinjection itself misses `1' -- ` with a trailing space.
- **Detector coverage is narrow on purpose** ("not a CRS clone"): `${IFS}` evasion, a schemeless `curl host`, `sleep N`, `python3` one-liners and a host-only `nc host` are missed by CmdI. For JNDI the Log4j `$${` escape is not modelled, and more than 8 nested `${` counts as a hit. CRLF checks only 8 named response headers. LFI misses the filter-evasion forms `....//`, `..././` and `/..;/`. SSRF misses the IPv4-compatible `[::127.0.0.1]` and NAT64 `64:ff9b::` forms, and reads all-digit hosts the inet_aton way. Probe paths match by prefix only (`/api/.env` is not matched), and the `~` backup-file suffix flags `/users/~`. `Transfer-Encoding` is compared exactly, so `Chunked` is blocked (which is the safe side).
- **NoSQL operators.** Query-string keys recognise ten operators (`ne`, `gt`, `gte`, `lt`, `lte`, `regex`, `where`, `in`, `nin`, `exists`); `$eq`, `$expr` and `$not` are missed. JSON keys are different: any key starting with `$` is a hit, so a legitimate `$schema` or `$ref` key is flagged. If your API takes JSON Schema documents, exclude `AEG-NOSQL-001` on that route and field.
- **Cookie names and JSON keys** are checked only by the key rules (`JSONKey`, `QueryKey`, `Session`), not by the full text detectors. That matters for a backend that uses a dynamic column or sort key taken from a JSON key or cookie name.
- **Raw rescan after malformed JSON.** When a body fails to parse, the raw bytes are rescanned in windows, using libinjection's quote-state context, so quote-parity padding can evade that rescan. This only matters where the backend would accept the same malformed body; most Go backends reject trailing data and syntax errors.
- **Multipart quoted-printable.** A malformed quoted-printable part aborts the multipart parse (`AEG-PROTO-020` only, monitor). The parts read before the failure are inspected. This mirrors Go backends, which also stop there.

### The four corpus misses

Both corpus gates pass with these requests still allowed (see [`testdata/corpus/README.md`](../testdata/corpus/README.md)):

1. **Content-type abuse on a `GET` with no body** (`Content-Type: application/x-evil-type`). The content-type allow-list applies only to requests with a body; with no body nothing parses the header.
2. **An operator inside a query value, not a key** (`q=[$ne]=1`). As a value it is inert text; the real shape (`q[$ne]=1`) is caught.
3. **XPath injection.** There is no XPath detector in v0.1 and libinjection does not flag it.
4. **An obfuscated `jndi` lookup in `X-Api-Version`** in the generic configuration only: that header is not scanned unless listed in `inspect_headers` (the API-aware corpus policy lists it). Only `User-Agent`, `Referer`, cookies and headers you list are scanned.

### Information in a match

- `Match.Snippet` is at most 64 bytes of the offending value, with control, format and bidi characters replaced. `Match.Field` can carry up to 256 attacker-chosen bytes of key text (a query key, a JSON path, a cookie name), sanitised the same way. Treat both as untrusted when you log or display them; never put them in a header or an HTML page unescaped.

### Servers and encodings

- **Smuggling headers on fasthttp.** fasthttp normalises the dangerous header combinations before the middleware runs: with both `Transfer-Encoding` and `Content-Length` it keeps `Transfer-Encoding`, duplicate `Content-Length` collapses to the last value, duplicate `Transfer-Encoding` to the first, and `xchunked` is rejected. The `AEG-PROTO` smuggling rules are a backstop there (and behind proxies that forward such headers differently). net/http neutralises the TE.CL variants itself.
- **`Content-Encoding` on Fiber.** `Body()` decodes a single supported encoding, so a compressed attack is inspected decompressed. Stacked or unusual encodings (`gzip, gzip`, `identity, gzip`) are not decoded; Fiber returns an error string, and that string is what Aegolith inspects. A handler that decodes the raw body itself would then see data Aegolith did not. Reject unsupported `Content-Encoding` upstream.
- **Decompression bombs.** The only bound is Fiber's `BodyLimit` on the compressed size. Set it to the largest compressed upload you accept and expect up to roughly 1000x expansion.
- **What the middleware reads.** It inspects the first `MaxBodyBytes + 1` bytes of the body. The body is read before the decision, so an `Expect: 100-continue` request has its `100 Continue` sent before a block can be decided. The handler still receives the complete original stream.

## Tests that back this up

- A corpus of 107 attacks and 91 legitimate requests, run twice (no policy, and a policy that types the fields) with no exclusions. See the [README](../README.md#corpus-results).
- Per-detector unit tests with the false-positive shapes beside each rule, including the accepted-recall negatives above.
- Fuzz targets for `Inspect`, the JSON walker and the value decoder (`make fuzz-quick`).
- Linear-time and scan-budget tests for adversarial inputs (long values, invalid UTF-8, deep or wide JSON), and a latency budget run (`make perf`).
- `go test -race` across both modules.

None of this is a proof. See [CONTRIBUTING.md](../CONTRIBUTING.md) for how to add a case when you find a gap.
