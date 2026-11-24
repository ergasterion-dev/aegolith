# Request corpus

The acceptance corpus for Aegolith's detection gates (spec §9.1). `corpus_test.go` at the repository root runs it twice:

| Test | Configuration | Gate |
|---|---|---|
| `TestCorpusGeneric` | `Config{Mode: enforce}`: no routes, no exclusions, every input untyped | blocked >= 95/107, false positives = 0 |
| `TestCorpusAPIAware` | `example-api-policy.json` (enforce, no exclusions) | blocked >= 99/107, false positives = 0, and every legitimate request fits the policy (no route or schema match) |

"Blocked" means `Decision.Action == Block`. Run with `make corpus` (`go test -run Corpus -v .`); the test prints a per-category table, the missed attacks and any false positive.

## Files

| File | What it is |
|---|---|
| `source/attacks.sh` | The ExampleCo WAF attack and false-positive suite, copied with a provenance header (Apache-2.0) and scrubbed of internal hostnames and personal contact details. Never run against anything here. |
| `gen.sh` | Regenerates `attacks.jsonl` and `legit.jsonl` from `source/attacks.sh`: it sources the script with its curl helpers replaced by functions that print the request each would send. Deterministic. Run from the repository root: `sh testdata/corpus/gen.sh`. Needs `python3`. |
| `attacks.jsonl` | 107 attacks, generated. |
| `legit.jsonl` | The 32 legitimate cases from the script, generated, followed by the contents of `legit.extra.jsonl`. |
| `legit.extra.jsonl` | Hand-written legitimate ExampleCo traffic: prose with `&`, `;`, `#`, `<`, `%`, Urdu and Hindi, apostrophes, links in reviews, decimal prices, pagination and sort, PUT/PATCH/DELETE, a multipart avatar upload with a JPEG part, cookies, `Accept-Language`, multi-line addresses, and the known false-positive candidates found while building the detectors. Edit this file, then rerun `gen.sh`. |
| `example-api-policy.json` | The ExampleCo-shaped route policy for the API-aware gate. |

## Line format

One JSON object per line:

```json
{"name":"classic tautology","category":"sqli","kind":"attack","method":"GET","path":"/api/v1/products/search",
 "query":[["q","1' OR '1'='1"]],"headers":{},"content_type":"","body":""}
```

- `path` is the raw (escaped) path, sent as is.
- `query` holds decoded pairs; the test percent-encodes them the way `curl --data-urlencode` does.
- `headers` are set as given; `content_type`, when not empty, sets `Content-Type`.
- `body` is the raw body. The optional `body_base64` replaces it for bodies a JSON string cannot carry byte for byte (the binary JPEG part of the multipart upload).

## Known misses

Both gates pass with these attacks still allowed. They are reported, not hidden:

| Attack | Generic | API-aware | Why |
|---|---|---|---|
| protocol / content-type abuse | missed | missed | A `GET` with no body and `Content-Type: application/x-evil-type`. The content-type allowlist applies only to requests with a body (spec 5.2); with no body nothing parses the header. |
| nosqli / operator in query | missed | missed | The suite sends `q=[$ne]=1`, so `[$ne]` arrives inside the value of `q`, not as a query key. As a value it is inert text; the query-key rule catches the real shape (`q[$ne]=1`). |
| misc / xpath injection | missed | missed | `' or name()='username' or 'x'='y`: libinjection does not flag it and there is no XPath detector in v0.1. |
| log4shell / obfuscated jndi | missed | blocked | The lookup is in `X-Api-Version`, which is scanned only when listed in `inspect_headers` (the API-aware policy lists it; the generic configuration scans `User-Agent` and `Referer` only). |
