# Alpha.7 part 2: XML by value and attack-rule improvements

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop judging XML markup as attack text, and catch more real attack techniques without new false positives.

**Architecture:** XML bodies are tokenized and their values scanned, as JSON bodies are. Each new technique is a narrow, hand-written check inside the existing detector for its family, behind a cheap substring gate.

**Tech Stack:** Go, standard library (`encoding/xml`) and `libinjection-go`.

**Spec:** `docs/superpowers/specs/2026-11-27-aegolith-alpha7-design.md`

## Global Constraints

- Public repository: no private product names, hosts, IPs, customer data, local paths or private report names in code, docs, tests or commit messages.
- Write every test payload yourself. Never copy text from a third-party attack set. Do not open `bench/.sources/`, `bench/out/` or `docs/bench/`.
- Rule work uses development and baseline cases only. Use the measurement script and case file the dispatch names; never fetch or build other case sets.
- A false positive is worse than a missed probe. A change that newly flags any legitimate development or baseline case is not done.
- Core dependencies stay stdlib plus `libinjection-go`. No regular expression on the per-value hot path unless it runs only after a substring gate and its cost is measured.
- Each new check is gated by a fixed substring (the anchor) so values without it pay only the search, and runs in time linear in the value.
- Latency budget: p99 < 50 us per request. Report `go test -bench` figures before and after for `ScanText`.
- Never log full request values (use `model.Redact`).
- TDD: watch each new test fail first. Every detection has a legitimate counter-case; every accepted false positive and accepted miss is listed in `docs/threat-model.md` and pinned by a test.
- Commit to `main`, `git push origin main` after every commit, Conventional Commits, `git add` named files only, never bypass the hook. No GitHub Actions.
- `make ci` exit 0 before the final commit of a task.

## Review Focus

1. Ordinary XML (namespaces, `<link>`, `<style>`, SOAP envelopes) passes (Task 1).
2. Text split by XML comments or CDATA is judged as the handler reads it (Task 1).
3. Malformed XML, wrong encodings and entity definitions never leave a value uninspected (Task 1).
4. A long hostile value cannot make a new check quadratic (Tasks 2-5, one linear-time test each).
5. Prose that contains an anchor (`<<<3`, `/???`, `like it--`) passes (Tasks 2-5).

---

### Task 1: Read XML bodies by value

**Files:** Modify `internal/engine/inputs.go`; create `internal/engine/xml.go` and `internal/engine/xml_test.go`; update `internal/engine/body_types_test.go`, `README.md`, `docs/threat-model.md`, `docs/architecture.md`, `CHANGELOG.md`, `fuzz_test.go` or the existing XML-declaration fuzz target.

**Interfaces:** Produces `func (s *state) checkXML(body []byte, cut bool)`, called from the XML branch of `checkBody`.

**Behaviour:**
- The XXE rule reads the raw body in windows exactly as today (it must catch everything it caught before).
- The body is tokenized with `encoding/xml` (strict). A declared ISO-8859-1, Latin-1, Windows-1252 or US-ASCII charset is converted byte by byte (each byte becomes the code point of the same value); any other declared charset passes through unchanged.
- Scanned with all text detectors, field `body`: character data (adjacent runs, including CDATA and runs separated only by comments or processing instructions, are joined into one value) and attribute values. Not scanned: element names, attribute names, namespace declarations (`xmlns`, `xmlns:*`), comments, directives, the XML declaration. A processing instruction other than the declaration has its content scanned; one whose target is `php` (any case) is scanned rebuilt as `<?php ...?>`.
- Joining runs and building values is linear in the body size.
- Elements whose local name is `script` (ASCII case-insensitive), and elements in the XHTML or SVG namespace, are also scanned as a rebuilt start tag (`<name attr="value">`), so markup an application would render is still judged.
- Fallback: on any tokenizer error (other than the unexpected end of a body cut at the inspection limit, which reports nothing) report `AEG-PROTO-020`, and on nesting deeper than `MaxDepth` report `AEG-PROTO-010`; in all three cases scan the raw body in windows, so nothing after that point goes unseen.
- More values than `MaxFields`: report `AEG-PROTO-010` once and keep reading value by value, as the JSON walk does.
- The OpenDocument binary prefix no longer covers XML: a type under it ending `+xml` or `-flat-xml` is XML.
- The spec's XML paragraphs (the XML group, the declaration paragraph, the known false positive and the first open follow-up) are rewritten to describe this behaviour, and false positives this removes leave the documented lists.
- The leading-declaration hiding added in part 1 is removed with its regular expression and tests that only exist for it; legitimate cases stay.

- [ ] **Step 1: Failing tests** (enforce and monitor as needed):
  - `TestXMLMarkupIsNotAnAttack`: a default namespace `<order xmlns="urn:example:orders">...`, an Atom feed with `<link href="https://example.com/a"/>`, `<style>bold</style>` as a data element, a SOAP envelope, `<?xml-stylesheet href="a.xsl"?>`, an ISO-8859-1 declaration with a raw byte 0xE9 in the text: allow, no match.
  - `TestXMLValuesAreScanned`: the SQL attack `1' UNION SELECT password FROM users--` as element text, as an attribute value, inside CDATA, and split as `1' UNI<!-- x -->ON SELECT password FROM users--`: `AEG-SQLI-001` on `body`; `&lt;script&gt;alert(1)&lt;/script&gt;` as element text: `AEG-XSS-001`.
  - `TestXMLRenderedElements`: `<script>alert(1)</script>` as a child element and `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>`: `AEG-XSS-001`.
  - `TestXMLFallback`: unclosed element followed by the SQL attack, an undefined entity before the attack, depth over `MaxDepth`: the attack is reported, and the protocol rule is present.
  - `TestXMLProcessingInstructions`: `<?php system($_GET['c']); ?>` inside an element reports a code or command injection rule; `<?mso-application progid="Excel.Sheet"?>` passes.
  - `TestXMLManyValues`: more elements than `MaxFields` reports `AEG-PROTO-010` only, and an attack after the limit is reported.
  - `TestOpenDocumentXMLTypes`: `application/vnd.oasis.opendocument.text-flat-xml` with an XXE body reports `AEG-XXE-001`.
  - `TestXMLXXEUnchanged`: the existing XXE cases pass unchanged.
- [ ] **Step 2:** `go test ./internal/engine/ -run XML -count=1` fails.
- [ ] **Step 3:** Implement. Respect the scan budget and `s.stop`.
- [ ] **Step 4:** Tests pass; add or retarget a fuzz target over `checkXML` and run it 30 s; benchmark a 4 KiB XML body before and after and report both; time a 1 MiB body of tiny elements and of comment-split text and report it against the documented worst case.
- [ ] **Step 5:** Docs, `make ci`, commit `fix: read XML bodies by value instead of raw markup`, push.

### Task 2: Command injection techniques (`AEG-CMDI-001`)

**Files:** `internal/detect/injection.go` or a new focused file beside it, with its test file; docs and CHANGELOG.

- **Here-string:** a letter, digit or `_` immediately followed by `<<<`, optional blanks and an optional quote, then a letter or `_`. Flag `cat<<<uname`, ``;tac<<<id``. Pass `miss you<<<3`, `x = <<<EOT`, `<<<<<<< HEAD`.
- **Glob to a system file:** a token starting `/` at the value start or after a blank or one of ``;|&+`(,{'"=<>``, containing `?`, `*` or `[...]`, which glob-matches (bash rules: `[!` negates, a `/` inside brackets is dropped) one of `/etc`, `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/hosts`, `/etc/issue`, `/bin/{sh,bash,cat,ls,nc,id}`, `/usr/bin/{cat,id,whoami,wget,curl,nc,bash,sh}`, `/usr/sbin/bash`, `/dev/tcp`, `/proc/self/environ`; the last segment must hold at least one letter. Flag `/???/?a?h`, `/e?c/pa[s]swd`. Pass `The redirect went to /???`, `ls /usr/bin/py*`, `/usr/bin/*`.
- **Windows FOR after an operator:** `&`, `|`, `;`, `&&` or `||`, blanks, `for` (any case), optional `/D`, `/L`, `/R`, `/F` switches with an optional quoted option string or path, a `%`/`%%` variable of 1-16 characters from `[A-Za-z0-9_~@\[\]]`, `in`, `(...)`, `do` as a word. Flag `& for %q in (x) do y`. Pass the same loop with no operator before it.

- [ ] Failing tests (each flag and pass string above, plus `TestNewCmdIChecksLinear` on 1 MiB hostile values), implement, measure, docs, `make ci`, commit `feat: detect here-strings, globbed system paths and chained FOR loops`, push.

### Task 3: SQL techniques (`AEG-SQLI-001`, `AEG-SQLI-002`)

- **Postgres JSON operators and casts** (in `AEG-SQLI-001`'s post-libinjection checks): a single-quoted literal (read at most 200 bytes) preceded by `or`/`and` plus blanks, or followed by `::json`/`::jsonb`, then after blanks one of `@>`, `<@`, `?|`, `?&`, `#>`, `#>>`, `->`, `->>`, `?` then a quote, or a `::json`/`::jsonb` cast; also a literal cast with `::json`/`::jsonb` followed by `|| '` or `- <digit>`; also `)::int|integer|bool|text` followed by `and`, `or`, another `::` or the end. Pass `data->>'name'`, `'{}'::jsonb`.
- **Quote breakout, operator, trailing comment:** (a) a letter or digit glued to `'`, a glued keyword `and|or|xor|not|is|mod|glob|like|regexp|rlike|collate`, at most 64 quote-free bytes, ending `--` or `#` then only blanks or `-`; (b) `'`, blanks, `xor|mod|div|glob|regexp|rlike|similar to|collate|sounds like`, at most 64 bytes, ending `--`, `#` or `;`; (c) `'`, blanks, one of `^&|%<>~-`, blanks, a name, `--` at the end; (d) `\'`, then `and`/`or`, then `name(...)` ending `;`. Pass `Kids' like it--`, `I said 'no' or else--`.
- **Delay inside an expression** (`AEG-SQLI-002`): `sleep(` or `benchmark(` following `),`, a digit and `,`, `(select`, `select `, `and `, `or `, `by ` or `if(`, with an argument starting with a digit, `(`, `mod(` or `select`. Pass `(sleep (2))` in a routine list. Update accepted-miss item 5 in the threat model.

- [ ] Failing tests for each shape and counter-case, linear-time test, implement, measure, docs, `make ci`, commit `feat: detect Postgres operator, comment-terminated and nested delay SQL injection`, push.

### Task 4: Template, PHP and LDAP techniques

- **Perl interpolation** (`AEG-SSTI-001`): `@{`, optional blanks, `[`, 1-128 bytes other than `]` or a line break, `]`.
- **PHP dynamic calls** (`AEG-CODEI-001`): (a) `(`, a quoted `system|exec|shell_exec|passthru|popen|proc_open|assert|eval|phpinfo|create_function|call_user_func`, `)`, `(`; or that quoted name directly followed by `(`; or `[system][0](`; or the unquoted name in `(...)` then `(` where the argument starts with a quote or `$`, or the call ends `);`; or `<?`, whitespace, then `php|echo|print|system|exec|$`. (b) `${...}(`, `$$name(`, `$name` with one or more `[...]`/`{...}` indexes then `(`, `@$name(`, `$_name(`; `/* */` allowed before `(`. The `${...}(` form is flagged only when the call argument starts with a quote or `$`, or the call ends `);`. Pass `$t('x')`, `$emit('y')`, `$('div')`, `$$('div')`, `$_('id')`, `Operating (system)(Linux)`, `Total ${amount}(incl. tax)`.
- **LDAP** (`AEG-LDAP-001`): `)(attr~=` or `)(attr=*`; `)` then `!`, `&` or `|` then `(attr=`/`~=`/`>=`/`<=`; `(` then `|`, `&` or `!` then `(attr=`; `)(&)` or `)(|)`; `attr:1.2.3:=`. `attr` is 1-41 bytes of letters, digits, `.`, `_`, `-`, starting with a letter. Pass `f(x)(y=2)`, `Pages (intro)(page=4)`.

- [ ] Failing tests, linear-time test, implement, measure, docs, `make ci`, commit `feat: detect Perl interpolation, PHP dynamic calls and more LDAP filters`, push.

### Task 5: Mail commands, scanner paths, SSRF spellings

- **Mail commands after a line break** (`AEG-CRLF-001`): CR, LF or CRLF, optional blanks, then upper-case `MAIL FROM:` + blanks + `<`; `RCPT TO:` + an address; `EHLO`/`HELO` + a host; `AUTH PLAIN|LOGIN|CRAM-MD5|XOAUTH2`; `RETR n`; `TOP n n`; an IMAP tag (a letter and three digits) + `LOGIN|AUTHENTICATE|SELECT|FETCH|STORE|COPY|APPEND|SEARCH|UID|LIST`; a short tag + `STORE n`. Pass a closing line `QUIT`, `MAIL FROM: the team`.
- **AI-assistant files at the path start** (`AEG-SCANNER-002`, path only, whole-name rule as the existing root dot names, same declared-route excuse): `.claude`, `.cursor`, `.cursorignore`, `.continue`, `.windsurf`, `.zed`, `.roo`, `.kiro`, `.junie`, `.opencode`, `.plandex`, `.rovodev`, `.a0proj`. Pass `/repo/files/.claude/x`.
- **SSRF spellings** (`AEG-SSRF-*`): read `http:host` and `http:/host` as `http://host/`, and map U+3002, U+FF0E, U+FF61 to `.` before classifying the host. Public hosts stay clear. Pass `the http:status header` and `http:error codes`.

- [ ] Failing tests, linear-time test, implement, measure, docs, `make ci`, commit `feat: detect mail command injection, assistant config probes and slashless URLs`, push.

## After the tasks

Whole-branch review; `make perf` and `make fuzz-quick` on a quiet machine; one bench run with `PREVIOUS` set to the first report's JSON (held-out totals read once); publish the report unedited from a clean pushed commit; CHANGELOG version section. The tag is the maintainer's.
