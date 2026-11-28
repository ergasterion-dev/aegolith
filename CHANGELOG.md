# Changelog

## Unreleased

### Template, PHP and LDAP techniques (`AEG-SSTI-001`, `AEG-CODEI-001`, `AEG-LDAP-001`)

- **New `AEG-SSTI-001` detections:** Perl interpolation (`@{[ ... ]}`).
- **New `AEG-CODEI-001` detections:** a short PHP tag followed by blanks (`<? echo`, `<? $x`), a listed function named in quotes or parentheses and called (`('system')(...)`, `"exec"(...)`, `(system)('...')`, `[system][0](`), and calls of a variable (`$_GET[...](...)`, `${...}('...')`, `$$name($x)`, `@$name(`, `$_name('...')`).
- **New `AEG-LDAP-001` detections:** `)(attr=*` and `)(attr~=`, `)&(attr=` and the like, `(|(attr=`, `(&(attr=` and `(!(attr=` anywhere, `)(&)`, `)(|)` and extensible matches (`attr:1.2.840.113556.1.4.803:=`).
- Clear: `$t('x')`, `$('div')`, `Total ${amount}(incl. tax)`, `` `${name}(${id})` ``, `page.$$eval(...)`, `this.$refs['form'](x)`, `$$f(x) = x^2$$`, `$a_{n}(x)$`, `require('assert')(ok)`, `f(x)(y=2)`, `if(!(a==b))`, `if(!(n=read()))`.
- **False positives to expect:** pasted PHP, Perl, jQuery or template-string code that calls what a variable holds, a mention or password written like a call with PHP's error suppression (` @$user(admin)`; after a symbol such as `!@$` only with a quote or a variable as the argument, an indexed name or a `${...}(` or `$$name(` shape), an LDAP filter pasted into a text field, and conditions or masks written without blanks (`if(!(x=y))`, `(x>0)&(y<=5)`). Exclude the rule on a field that carries such text ([every accepted false positive and miss](docs/threat-model.md#template-php-and-ldap-techniques-added-in-alpha7), including the readings that can be used to evade a check).

### Bodies of every non-binary content type are inspected

- Before, a body was inspected only when it was JSON, a urlencoded form, multipart, `text/*`, or (with `allow_xml`) `application/xml`. XML, SOAP and other textual bodies (`application/soap+xml`, `application/graphql`, `application/yaml`, ...) allowed through `allowed_content_types` or a silenced `AEG-PROTO-002` were not inspected. They are now scanned as text and **can now block**. A body without a content type is scanned the same way.
- The XXE rule (`AEG-XXE-001`) now runs on every inspected XML body (`application/xml`, `text/xml`, `+xml`), also without `allow_xml`.
- [Binary types](docs/threat-model.md#binary-bodies) are still not inspected, `image/svg+xml` among them. An allowed binary type that is not on that list is read as text and can block (for example `AEG-LFI-001`); exclude each rule that matches on field `body` for that route.
- An XML body is now [read by value](docs/threat-model.md#xml-bodies) instead of as raw markup: the text detectors read its character data (adjacent runs joined, across CDATA, comments and processing instructions), attribute values and processing instructions, not element or attribute names, namespace declarations, comments, a `DOCTYPE` or the leading declaration. alpha.6 blocked ordinary XML with `AEG-XSS-001` wherever it read it (`allow_xml`, or `text/xml`): a declaration, a default namespace (`xmlns="..."`), an Atom `<link href="...">`, an RSS `<link>https://...</link>`, a bare `<!DOCTYPE note>`, a `<style>` element, `<?xml-stylesheet ...?>`. These are now clear. A body is tokenized only without a declared charset or with an ASCII-compatible, stateless one (`UTF-8`, `US-ASCII`, `ISO-8859-*`, `Windows-874`, `Windows-125x`, `Shift_JIS`, `EUC-JP`, `EUC-KR`, `GB2312`, `GBK`, `GB18030`, `Big5`, `KOI8-R`, `KOI8-U`, and their standard aliases such as `utf8`, `latin1`, `cp1252` or `sjis`), read byte by byte; any other charset (`UTF-16`, `UTF-7`, `ISO-2022-JP`, EBCDIC), and a namespace prefix bound to `xmlns` or `""`, are treated as a parse error and the raw body is scanned.
- Elements a browser would render (`script` in any vocabulary, the XHTML and SVG namespaces) are also read as a rebuilt start tag. A body that does not parse raises `AEG-PROTO-020` (monitor), nesting deeper than `max_depth` and more values than `max_fields` raise `AEG-PROTO-010` (monitor); after a parse error or a depth overflow the raw body is scanned as text.
- OpenDocument flat XML types (`application/vnd.oasis.opendocument.text-flat-xml`, and any `+xml` type under that prefix) are XML, no longer binary.
- **False positives to expect:** an element named `script` (`<script>backup.sh</script>`), an `svg` element in the SVG namespace, XHTML `style`, `link` or `meta` elements and a `style` attribute on an XHTML or SVG element match `AEG-XSS-001`. **New:** escaped HTML in text, as a feed carries it (`&lt;p style=&quot;color:red&quot;&gt;`, an escaped `&lt;iframe ...&gt;`), is read unescaped, as in a JSON string, and now matches `AEG-XSS-001` (alpha.6 read the escaped form and let it pass); so can markup in an XML body that does not parse (for example an entity declared in a `DOCTYPE`, such as `&nbsp;`), whose raw text is then scanned. Exclude the rule on field `body` for that route.
- **Missed by design:** an attack in a comment, an element or attribute name or a namespace declaration, text split across child elements, and a payload that is an attack only once decoded from a multi-byte or non-Latin charset.
- **Cost:** the costliest XML bodies read every value (a declared charset read byte by byte doubling high bytes) and then fail late, paying the raw rescan as well; measured on a loaded machine at about the JSON worst body (0.57 to 1.39x in the same process, about 127 MB), to be re-measured before the tag.
- With the default configuration, enforce mode decides as before: a refused type blocks before the body is read. Monitor mode now also reports what is in such a body.

### New field types `base64` and `base64url`

- A route can declare a path parameter, query value, form field or JSON body field `base64` (`aegolith.TypeBase64`) or `base64url` (`aegolith.TypeBase64URL`). The value is decoded, and the detectors judge the decoded text as they judge a JSON body value, wherever it was sent (so a query value that decodes to several lines is not read with the query string's command rule); the encoded text is not scanned. Path-level rules (`AEG-PROTO-005`, the scanner path rules) see only the encoded path of a path parameter ([what is missed](docs/threat-model.md#base64-fields)).
- `base64` takes the standard alphabet (`+` `/`) only, `base64url` the URL-safe one (`-` `_`) only. On a `base64url` field the handler must decode with a URL-safe decoder.
- Padding is optional but correct when present, CR and LF are ignored. Anything else is `AEG-SCHEMA-001`. `max_len` bounds the encoded value.
- Meant for base64-encoded text: binary content would be scanned as text and can block.
- Nothing is decoded outside declared fields, so a configuration without these types decides as before.

### A declared template that ends in `/` no longer excuses the path without it

- With `GET /actuator/health/` declared, `GET /actuator/health` was not flagged by the scanner path rules (a gap in alpha.6, found after the tag; alpha.5 flagged it), although another handler may answer it. `AEG-SCANNER-002` and `AEG-SCANNER-003` report it again, also as `HEAD` and, when routes fold case, in another letter case. The form with the slash stays clear, and so does the template `/`.
- **False positives to expect:** a client that drops the final slash of such a template, where the text is a probe name or a backup file, is flagged and, in enforce mode, blocked, also where the declared handler would serve the request (Fiber without `StrictRouting`, or with a parameter in the template) or `ServeMux` would redirect it to the declared form. If your clients send the form without the slash, declare the template without it (a probe name on the slash form is then flagged only where the rule reads it: `/actuator/health/` and a first-segment archive such as `/backup.zip/` are flagged, a backup file that ends the path, such as `/b/y.php.bak/`, reports nothing). To allow both, exclude the rule on that route: `{"rule": "AEG-SCANNER-002", "route": "GET /actuator/health/", "field": "path"}`, with `AEG-SCANNER-003` as the rule for a backup file or archive (the rule is then off for the path of that whole route, parameters included).

### More SQL injection techniques (`AEG-SQLI-001`, `AEG-SQLI-002`)

- **New `AEG-SQLI-001` detections:** Postgres JSON operators and casts on a literal (`'{...}'::jsonb @> ...`, `or '{...}' @> '{...}'`, `)::int and`), and a quote breakout that ends in a comment or `;` (`x'or ... --`, `x' mod ... #`, `x' ^ name--`, `\' or f();`).
- **New `AEG-SQLI-002` detections:** MySQL `sleep(` and `benchmark(` inside an expression (`if(sleep(5)`, `and benchmark(...)`, `1,sleep(5)`).
- Clear: `data->>'name'`, `'{}'::jsonb`, `(total * 100)::integer`, `Kids' like it--`, `I said 'no' or else--`, `sql += ' collate nocase';`. The new delay check leaves `(sleep (2))` and `eat and sleep(8 hours)` alone (`AEG-SQLI-001` flagged both before, and still does).
- **False positives to expect:** SQL pasted into a text field that applies a JSON operator to a literal or casts a subquery, a rare unmatched apostrophe before an SQL word in a value that ends in `--` or `#`, and prose written like a delay call (`recover by sleep(8)`). Exclude the rule on a field that carries such text ([every accepted false positive and miss](docs/threat-model.md#sql-techniques-added-in-alpha7)).

### Three more command injection techniques (`AEG-CMDI-001`)

- **New detections:** a here-string written against a word (`cat<<<uname`); a rooted glob that matches a listed system file or program (`/???/?a?h`, `/e?c/pa[s]swd`); and a Windows `FOR` loop chained to another command (`& for %q in (x) do y`). Query and body values alike; in a query value a glob may also start after a line break (`?q=x%0a/???/?a?h`).
- Clear: `miss you<<<3`, `x = <<<EOT`, Git conflict markers, `/???`, `/usr/bin/*`, `/usr/bin/py*`, `/[a-z]*`, a root-relative link such as `next=/?tc=1`, and a batch loop with no operator before it.
- **False positives to expect:** `Back<<<Home` or PHP `echo<<<EOT`; a shell glob in text that covers a listed file (`ls /usr/bin/c*`, `/etc/hosts*`), a short pattern such as `/e*` or `/*/id` (in a query value also at the start of a later line), a link with a valueless parameter such as `/?tc`; a batch snippet such as `@echo off & for %%i in (*) do ...`. Exclude `AEG-CMDI-001` on a field that carries such text ([every accepted false positive and miss](docs/threat-model.md#command-injection-techniques-added-in-alpha7)).

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

### Known gap found after the core tag

- **Declared templates that end in `/` (new in alpha.6).** A declared template that ends in `/`, requested without that slash, is excused: with `GET /actuator/health/` declared, `GET /actuator/health` is not flagged (alpha.5 flagged it), and another handler may answer it. Fiber with `StrictRouting` serves it with a later `/actuator/:ep`, `/actuator/*` or catch-all handler, if there is one, when the template has no parameter; Go's `ServeMux` serves it with a pattern that matches the slashless path itself, such as `/actuator/{ep}`. If another handler could answer that path, register the route and declare its template without the final slash. Fixed after the tag; see [Unreleased](#unreleased).

### Performance

Measured at commit `b0c0ec0` on a loaded Apple M4 Pro laptop (go1.25.12), alternating with alpha.5. **The latency budget (p99 under 50 µs) did not hold in every run, with either release.** Over two sessions of six runs (the second at a lower load), a run had at least one row over budget in 3 of 12 runs for alpha.6 on its 195 corpus requests (p99 56.0 to 84.7 µs), 4 of 12 for alpha.6 on alpha.5's 130 requests and policy (62.5 to 87.0 µs) and 4 of 12 for alpha.5 (56.5 to 111.8 µs). Every row over budget had browser headers, and the slowest single request in those latency runs took 19.5 ms. On identical requests alpha.6 is slower: median p50 13 to 19% and median p99 11 to 24% higher. Benchmarks (lowest of rounds 4 to 6 of six; two alpha.6 runs in the earlier rounds ended with a 5-minute load above 10, the level each run had to start below) are slower too: search GET and cart POST by 14 to 21% (generic: search GET 12.1 to 14.3 µs, cart POST 17.4 to 19.9 µs), the per-request corpus benchmark on alpha.5's requests and policy by 7% (generic) and 17% (api-aware), `ScanText` on a short word from 105 to 115 ns, and the worst-case 1 MiB bodies by 4 to 6% (460 ms for the slowest body in its lowest run). Details in the [README](README.md#performance).

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
