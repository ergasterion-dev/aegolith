# Changelog

## v0.1.0-alpha.5

False positives found in the alpha.4 production test, plus one missed deserialization shape. Corpus: 137 attacks (133 blocked generic, 134 API-aware) and 130 legitimate requests, 0 false positives (was 132 and 118). Costs and limits are in the [threat model](docs/threat-model.md#changes-in-alpha5-and-what-they-cost).

- **CmdI, `sleep N` after one word of prose.** `Mon; sleep 8`, `Gate 2; sleep 10`, `Good night; sleep 8`, `Tired & sleep 8` and `Café; sleep 8` are no longer flagged. Still flagged: a leading operator (`; sleep 10`, `;sleep 10`), `|` and `&&`, no blank after the `;` (`1;sleep 5`, `Mon;sleep 8`), any operator after the number (`Mon; sleep 8 &`), a token before `; ` that is not a plain word or number (`127.0.0.1; sleep 10`, `file.txt; sleep 10`, `a=1; sleep 10`), and a `;` that is still percent-encoded after decoding (`Mon%3B%20sleep%208`, treated as a scanner). **Recall given up:** a single plain token, then `; `, then `sleep N` at the end of the value (`x; sleep 10`, `1; sleep 5`, also with two blanks) is no longer caught. Other commands after a one-word prefix are unchanged (`Mon; id`, `Passport; "id"` are still flagged).
- **SSTI, `${...}`.** Plain member access and calls are no longer flagged: `${order.total}`, `${user.name}`, `${file.txt}`, `${price}`, `${a.b.c}`, `${order.key}`, `${student.class}` are clean. A `${...}` is flagged for arithmetic (`${7*7}`), a sensitive name (`password`, `pass`, `pwd`, `secret`, `token`, `credentials`, `apikey`, `env`, `getclass`, `forname`, `runtime`, `system`, `classloader`, `execute`, `eval`, `session`, `request`, ...; the full set is in `elSensitive`), a call with a string-literal argument, a `__` (dunder), `?new` or `?api`, or a string-literal receiver (`${"id".execute()}`). **Costs:** `${t('cart.title')}` (an i18n call with a string argument) and `${bus.pass}` are now flagged. **Recall given up:** member access or calls on non-sensitive names (`${user.getName()}`) are no longer detected. `#{order.total}` is still flagged. `${jndi:...}` stays with the JNDI rule.
- **CodeI (G1b).** A base64 Java serialized object after a `/` in a path (an unknown route, or the rest of a wildcard route) is now `AEG-CODEI-002`. The marker after a `/` is `rO0ABX`, not `rO0AB`, so a long legitimate path segment does not match.
- **Example policy:** a new route `GET /api/v1/files/:key` (string, max length 200) in `testdata/corpus/example-api-policy.json`, used by the new path near-misses.
- Known and unchanged: libinjection flags numeric tautology prose such as `6-7 or 8` (`AEG-SQLI-001`); exclude it on the field.
- Performance and benchmark numbers were not re-measured on a loaded machine (load average 16 or more at release time); the README figures are from alpha.3.

## v0.1.0-alpha.4

Detector gaps found by probing a production API. Corpus: 132 attacks (128 blocked generic, 129 API-aware) and 118 legitimate requests, 0 false positives (was 107 and 91). Costs and limits of each item are in the [threat model](docs/threat-model.md#detector-coverage-added-in-alpha4-and-what-it-costs).

- **SQL injection after leading words or padding** is caught by also reading from SQL keyword starts (the first 8 and the last 8 qualifying candidates, each read for at most 128 bytes). Residual: more than 8 qualifying non-triggering candidates on both sides of a payload. Known false positive: `call 1 or 2=3 --`. The libinjection false positive on numeric tautology prose (`6-7 or 8`) is not new; it is now documented.
- **XSS:** a nested or broken `<script` tag is caught anywhere in a value.
- **SSTI:** Go template actions with a function (`printf`, `call`, `index`, ...) and `${...}` expressions (`${7*7}`, member access, calls). `${a.b}` in free text was a deliberate false positive; alpha.5 narrowed this, see above.
- **CmdI:** `sleep N`, command words split by quotes or backslashes, and a bare command after an encoded line break in a query value. Trade-off: a real line break plus a bare command word in a query value is now a hit. Not caught: form-body `x%0aid`. Cost: `Passport; "id"` and `Tea & 'cat' /etc/passwd` are flagged. (alpha.4 also flagged `Gate 2; sleep 10` and `Mon; sleep 8`; fixed in alpha.5.)
- **Scanner:** the dot names (`/.env`, `/.git/`, `/.aws/`, `/.ssh/`) and `/wp-login.php` match at the start of any path segment (`/api/v1/.env`); `actuator` below the first segment only with a known endpoint after it (`/api/v1/actuator/env`, not `/api/v1/devices/actuator/5`); `wp-admin`, `phpmyadmin` and `server-status` still match at the path start only; new user agents `wfuzz`, `feroxbuster`, `Fuzz Faster U Fool` and `Hydra`.
- **Keys:** SQL injection is checked on JSON, query, form and multipart key names; prototype pollution in query and form keys (`__proto__[x]`, `a.constructor.prototype.x`); a lone `constructor` or `prototype` query key is not flagged. A key over `max_value_len` raises `AEG-PROTO-011`.
- **Fiber adapter, over-cap bodies:** up to `2 x max_body_bytes + 1` bytes are copied in every mode. **Release note:** enforce with `AEG-PROTO-003` set to monitor now inspects up to twice the limit, and an over-cap body costs one more copy of at most `max_body_bytes`. The net/http adapter still copies `max_body_bytes + 1`. A JSON or multipart body cut only by the inspection cap no longer raises `AEG-PROTO-020`; so with `AEG-PROTO-003` set to monitor and `AEG-PROTO-020` raised to block, an over-cap JSON or multipart body that the cap cuts, which was blocked through `AEG-PROTO-020` before, is now allowed.
- **Not supported (unchanged):** MySQL-only syntax, fullwidth, `%u` and overlong encodings, nip.io-style DNS SSRF, XPath injection, Python `__import__`.
- Performance and benchmark numbers were not re-measured on a loaded machine; the README figures are from alpha.3.

## v0.1.0-alpha.3

- **New field type `uuid_lenient`** (`aegolith.TypeUUIDLenient`), accepted wherever `uuid` is (path params, query values, JSON body fields). Besides the canonical `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` form it accepts the encodings Go's `github.com/google/uuid` `Parse` takes: 32 hex digits without dashes, the canonical form in `{` `}` and `urn:uuid:` plus the canonical form (hex and prefix in any ASCII case). Everything else is `AEG-SCHEMA-001`, including whitespace, NUL bytes, other brackets and nested braces (`Parse` accepts any two bytes around a 38-byte value; `uuid_lenient` does not). It is opt-in: use it only where the handler parses ids leniently.
- `uuid` is unchanged: canonical form only.
- The "unknown type" error from `New` now lists the known type names.

## v0.1.0-alpha.2

Behaviour changes since alpha.1 (read before upgrading):

- **`AEG-PROTO-003` (body over `max_body_bytes`) now blocks by default**, with severity medium (was monitor, low). This closes the "pad the body past the limit" bypass. To accept larger bodies, raise `max_body_bytes`; do not set the rule to monitor.
- **`LoadConfig` rejects an explicit `"allow"`** for top-level `unknown_route` / `unknown_fields`, with an error pointing to `rule_actions`.
- **Route matching:** new `case_insensitive_routes` option (the Fiber adapter enables it unless the app is `CaseSensitive`). When template cases collide, the most specific template wins, then the first declared.
- **`Decision`** gains `Route` and `Duration`. `Duration` varies per call, so two decisions for one request are no longer byte-identical.
- **`SlogHook`** logs route, locations and latency, and every field goes through the same sanitiser (non-ASCII bytes are logged as `?`).
- **NoSQL rule** now matches a fixed operator list (`$or $and $nor $not $size $elemMatch $exists $type $regex $where $expr $mod $all $in $nin $ne $gt $gte $lt $lte $eq $text $jsonSchema`); other operators such as `$geoWithin`, `$near` and `$bits*` are no longer flagged. Form keys like `amount[$USD]` no longer match.
- **Detectors:** fewer false positives for prose in the XSS script-URL and CmdI guards, `Location` CRLF check widened. Recall costs are listed in the threat model and corpus README (`x & cat /flag.txt`, `Location:evil.com` are missed).
- The Fiber adapter caches the app config once per middleware instead of per request.
- Docs: body-cap and `Content-Encoding` guidance, known gaps for trailing JSON data, non-UTF-8 charsets and the 8x scan-budget worst case.

## v0.1.0-alpha.1

First tagged release.
