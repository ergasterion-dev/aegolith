# Changelog

## v0.1.0-alpha.6

2026-11-26. Fixes the false positives found by an external validation of alpha.5 (public attack payload lists and benign text) and closes several cheap recall gaps. Corpus: 230 attacks (226 blocked generic, 227 API-aware) and 195 legitimate requests, 0 false positives (was 137 and 130). **Read [Changes in alpha.6](docs/threat-model.md#changes-in-alpha6-and-what-they-cost) and [Known gaps found in the alpha.6 review](docs/threat-model.md#known-gaps-found-in-the-alpha6-review) before upgrading:** every cost and accepted miss is listed there.

### New rule IDs (both block by default)

- **`AEG-SQLI-002`:** SQL time-delay and command-execution tokens: `WAITFOR DELAY` or `WAITFOR TIME` with a literal or `@variable`, `xp_cmdshell`, `pg_sleep(`, `pg_sleep_for(`, `pg_sleep_until(`, `DBMS_LOCK.SLEEP(`, `DBMS_SESSION.SLEEP(`. Also run on key names that are not plain identifiers.
- **`AEG-SSTI-002`:** server-side include directives (`<!--#exec cmd=`, `<!--#include virtual=`, `<!--#echo var=`, `<!--#printenv -->`, `config`, `set`, `fsize`, `flastmod`).

Excluding `AEG-SQLI-001` or `AEG-SSTI-001` on a field leaves the new rules on; exclude them by ID, or by a prefix such as `AEG-SQLI-*`. One exception: a key name that matches both SQL rules reports only `AEG-SQLI-001`, so excluding `AEG-SQLI-001` on that key, or setting it to `monitor` in `rule_actions`, also drops `AEG-SQLI-002` for it.

### Fixed false positives

- **SQLi:** product and ingredient text with percentages (`Sale 20% (today only)`, `80% ACRYLIC AND 20% WOOL`) and a bare size range (`6-7 or 8`).
- **CmdI:** the Indonesian locale token `; id;` / `; id)` in a User-Agent comment; `Tea & cat -cozy /club`; a markdown single-backtick span in a sentence (``Use `ls` to list files``) in JSON, form, header and cookie values; `id` or `ls` alone on the line after a prose line in a query value.
- **XSS:** a backtick inside an HTML comment (GitHub-style templates); placeholder tags such as `<link>` and `<Object>`; a mention of `<!DOCTYPE`; `javascript: yes=no; maybe (later)`.
- **SSTI:** placeholder filter pipes (`{{ price | currency }}`) and tldr option syntax (`{{[-p|--patch]}}`); `${t('cart.title')}`; `${bus.pass}`; plain data paths in `#{ }` (`#{order.total}`).

### New detections

- **CmdI:** `$(...)` and `$((...))` substitutions of any word (except where it reads as a prose dollar amount) and `echo` probes after a shell operator (commix's default probes); `x; sleep 10` and `1; sleep 5` are caught again.
- **SSTI:** `${7*'7'}`, a Ruby `%x` command in `#{ }`, a call before a nested `#{ }` (`#{system("id #{1}")}`), and a FreeMarker `?new(` on a class-name literal anywhere in a value. A nested `#{ }` is read as strictly as alpha.5 read it, with no plain-data-path exemption, so `#{system("id #{a.b}")}`, `#{"#{a.b}" + system("id")}` and ``#{`id #{a.b}`}`` stay flagged.
- **Scanner:** VCS directories (`.git`, `.svn`, `.hg`, `.bzr`) as whole segments at any depth; secret dotfiles and private keys at the path start; SQL dumps, SQLite files and archives as the first segment; the user agents `commix`, `netsparker`, `arachni`, `w3af`, `webinspect`, `havij`, `sqlninja`, `whatweb`, `detectify`, `jorgee`, `zmeu`, `paros`, `qualys was` and `vega/`.

### Behaviour changes an operator must know

- **Declared routes and scanner path rules.** A probe-path match (`AEG-SCANNER-002`, `-003`) is no longer reported when the matched text lies wholly in literal segments of the declared route the request matched, so `GET /api/v1/stores/:id/actuator/health` clears its own `actuator/health`. A match in a `:name` or `*` segment still counts, a root name such as `/actuator` or `/wp-admin` runs to the end of the path, and a trailing slash the template lacks or `%2F` in a parameter excuses nothing (so such a health check with a trailing slash stays blocked).
- **New false positives to expect:** shell snippets with `$(...)` or `echo $...` after an operator; the bare name `xp_cmdshell`, quoted SQL delay calls and prose such as `We waitfor time "to heal"`; a quoted SSI or ASP include, or a comment such as `<!-- # Set value = 1 -->`; a `.git`, `.svn`, `.hg` or `.bzr` segment anywhere in a path and a secret file name such as `/.npmrc` or `/id_rsa` as the first segment; an SQL file or archive served as the first path segment (`/app.zip`, `/main.js.map.gz`; compressed web, feed, manifest, icon and font files such as `/sitemap.xml.gz`, `/app.mjs.gz` or `/font.woff2.gz` are clear); an application whose own user-agent token is a scanner word (`Paros/2.1`, `Vega/1.0`); Ruby documentation prose with a call after an unclosed `#{` (`Ruby uses #{ for interpolation, see puts("hi #{name}") in the docs`). Text with a nested `#{` (`#{order #{user.name}} ready`) or an unclosed `#{` before a data path (`Use #{ to interpolate, as in #{user.name}`) is flagged as at alpha.5.
- **`#{ }` is still stricter than `${ }`:** a call, index, `*` or member access is code unless the whole expression is a plain data path that is not nested in another `#{`.

### Recall given up

- **SQLi:** comparison-free tautologies with a range or decimal, or after `N% (word)` (`1-1 or 1`, `9% (a) or 1`, `5% (x) or true`); a nested block comment inside an `AEG-SQLI-002` token (`pg_sleep/* /* */ */(5)`, which `AEG-SQLI-001` still flags).
- **CmdI:** a two-letter command in a User-Agent comment, after a prose line in a query value, or (with letter-only flags, any command word) in a prose backtick span; `x & cat -cozy /flag`.
- **XSS:** five shapes, the first being a one-word spaced call such as `javascript: a=1; alert (x)`.
- **SSTI:** bare filter pipes (`{{ x|config }}`), one-letter and `$t` calls with a plain string (`${e('id')}`), `${user.pass}`, and `#{ }` data paths, which can still call zero-argument methods (`#{order.destroy}`) or name a compound secret (`#{appConfig.dbPassword}`); a data path after a `}` inside a string, which counts as a close (`#{"}" + "#{a.b}" + system("id")}`).
- **Found in review and left as they are:** `/.git;x` and `/.git\config` are not probe paths, a single dot (`%2e`) in a parameter of a declared route is excused, `javascript: a=1, alert (document.cookie)` (a spaced call after a comma) is not flagged, and a Ruby call without parentheses (`#{system 'id'}`, also clear at alpha.5) is not flagged.

### Performance

Measured at commit `b0c0ec0` on an Apple M4 Pro laptop (go1.25.12, 5-minute load average 7.7 to 10.0), with alpha.5 run alternately on the same machine. Latency budget: the lowest p99 of 6 runs is 14 to 31 µs per legitimate corpus request against the 50 µs budget (alpha.5, on its smaller corpus: 10 to 26 µs), but **two of the six runs each exceeded the budget on one row** (84.7 µs and 65.7 µs); alpha.5 exceeded it in one of its six runs, on two rows (112 µs). Benchmarks, best of 3, are slower than alpha.5: search GET and cart POST by 14 to 21% (generic: search GET 12.1 to 14.3 µs, cart POST 17.4 to 19.9 µs), the per-request corpus benchmark on alpha.5's requests and policy by 7% (generic) and 17% (api-aware), `ScanText` on a short word from 105 to 115 ns, and the worst-case 1 MiB bodies by 4 to 6% (up to 460 ms). Details in the [README](README.md#performance).

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
