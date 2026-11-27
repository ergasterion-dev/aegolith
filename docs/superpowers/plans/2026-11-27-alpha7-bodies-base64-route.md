# Alpha.7 part 1: body inspection, base64 fields, trailing-slash gap

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Inspect every body that can reach a handler, add a `base64` field type, and close the trailing-slash scanner gap.

**Architecture:** All three changes sit in `internal/engine` (`inputs.go`) with one new type in `internal/policy`. No new dependency, no public API change except the new type constant.

**Tech Stack:** Go, standard library only.

**Spec:** `docs/superpowers/specs/2026-11-27-aegolith-alpha7-design.md`

## Global Constraints

- Public repository: no private product names, hosts, IPs, customer data, local paths or private report names in code, docs, tests or commit messages.
- Write every test payload yourself. Never copy text from a third-party attack set. Do not open `bench/.sources/` or `bench/out/`.
- Core dependencies stay stdlib plus `libinjection-go`.
- Never log full request values (use `model.Redact`).
- TDD: watch each new test fail before writing the code.
- Commit to `main`, `git push origin main` after every commit, Conventional Commits, `git add` named files only. Never bypass the commit hook.
- No GitHub Actions.
- Run `make ci` before the final commit of a task. Do not run `make perf` (needs a quiet machine).

## Review Focus

1. A legitimate XML body on a newly inspected type must not be blocked (Task 1 test).
2. An SVG upload on an allowed `image/svg+xml` must not be blocked (Task 1 test).
3. A media type with parameters or odd case (`Application/XML; charset=utf-8`) is classified the same (Task 1 test).
4. Legitimate base64 text with line breaks, unpadded or URL-safe, is accepted (Task 2 test).
5. A declared `/x/` template requested as `/x/` stays excused (Task 3 test).

---

### Task 1: Inspect bodies of every non-binary content type

**Files:**
- Modify: `internal/engine/inputs.go` (`checkBody`)
- Create: `internal/engine/body_types_test.go`
- Modify docs: `README.md` (settings rows `allowed_content_types`, `allow_xml`; `AEG-XXE-001` row), `docs/threat-model.md` (protection table row for XXE, and a short accepted-miss entry), `docs/architecture.md` (step 6), `CHANGELOG.md` (new `## Unreleased` section above alpha.6)

**Interfaces:**
- Produces: `func binaryMediaType(mt string) bool`, `func xmlMediaType(mt string) bool` (unexported, `mt` already lower-cased by `mediaType`).

**Order of the switch in `checkBody`:** JSON, urlencoded form, `multipart/`, binary (return), XML (`s.scanWindows(model.LocBody, "body", string(body), detect.XXE, "")`), default `s.scan(model.LocBody, "body", string(body))`. The `AllowXML` condition on the XML branch goes away.

**Binary set:** prefixes `image/`, `audio/`, `video/`, `font/`, `application/grpc`, `application/vnd.openxmlformats-officedocument.`; exact `application/octet-stream`, `application/pdf`, `application/zip`, `application/gzip`, `application/x-gzip`, `application/x-tar`, `application/x-7z-compressed`, `application/x-protobuf`, `application/protobuf`, `application/vnd.google.protobuf`, `application/msgpack`, `application/x-msgpack`, `application/vnd.msgpack`, `application/cbor`, `application/wasm`, `application/msword`, `application/vnd.ms-excel`, `application/vnd.ms-powerpoint`.

- [ ] **Step 1: Write the failing tests** in `internal/engine/body_types_test.go` with the package's `newEngine` helper. Each case builds an engine with `Options{Mode: model.ModeEnforce, FailOpen: true, AllowedContentTypes: []string{ct}}` (add `DefaultContentTypes` entries only if the case needs them) and sends a `POST /x` with that `Content-Type`.
  - `TestAllowedBodyTypesAreInspected`: body `<q>1' UNION SELECT password FROM users--</q>`; types `application/xml`, `Application/XML; charset=utf-8`, `application/soap+xml`, `application/vnd.acme+xml`, `application/graphql`, `application/yaml`, `application/x-made-up`: assert `Action == model.ActionBlock` and an `AEG-SQLI-001` match on field `body`.
  - `TestXXERunsOnEveryAllowedXMLType`: a self-written `<!DOCTYPE a [<!ENTITY b SYSTEM "file:///etc/hostname">]><a>&b;</a>`, `AllowXML: false`; types `application/xml`, `text/xml`, `application/soap+xml`; engine in `ModeMonitor`: assert an `AEG-XXE-001` match.
  - `TestBinaryBodyTypesAreSkipped`: same SQL body; types `image/png`, `image/svg+xml`, `audio/mpeg`, `video/mp4`, `font/woff2`, `application/octet-stream`, `application/pdf`, `application/grpc+proto`: assert allow and no match.
  - `TestLegitimateBodiesOnInspectedTypesPass`: `application/xml` with `<?xml version="1.0"?><order><sku>A-1</sku><qty>2</qty><note>Leave at the front desk, please.</note></order>`; `application/soap+xml` with the same wrapped in a `soap:Envelope`/`soap:Body`; `application/graphql` with `query { products(first: 10) { id name price } }`; `application/yaml` with `name: demo\nitems:\n  - sku: A-1\n    qty: 2\n`: assert allow and no match.
  - `TestMissingContentTypeBodyIsInspectedWhenAllowed`: monitor mode, default options, no `Content-Type`, SQL body: assert `AEG-SQLI-001` on `body` and `AEG-PROTO-002`.
  - `TestRefusedTypeStillBlocksBeforeBodyScan`: default options, enforce, `Content-Type: application/xml`: assert the only match is `AEG-PROTO-002`.
- [ ] **Step 2:** `go test ./internal/engine/ -run 'BodyType|XXE|Binary|Legitimate|MissingContentType|RefusedType' -count=1` — expect failures in the inspected-types, XXE and missing-type tests. If a legitimate case matches a rule after the change, do not weaken a detector: report it with the rule ID.
- [ ] **Step 3:** Implement the two helpers and the switch.
- [ ] **Step 4:** Re-run Step 2 (pass), then `make ci` (exit 0).
- [ ] **Step 5:** Update the docs listed above. The CHANGELOG entry states that XML, SOAP and other textual bodies allowed through `allowed_content_types` or a silenced `AEG-PROTO-002` were not inspected before and now can block.
- [ ] **Step 6:** Commit `fix: inspect bodies of every allowed non-binary content type` and push.

### Task 2: `base64` field type

**Files:**
- Modify: `internal/policy/field.go`, `internal/engine/inputs.go` (`typed`), `aegolith.go` (export the constant beside `TypeUUIDLenient`)
- Test: `internal/policy/base64_test.go`, `internal/engine/base64_test.go`
- Modify docs: `README.md` (field type table and a short note on use), `docs/architecture.md` if it lists scanned types, `CHANGELOG.md`

**Interfaces:**
- Produces: `policy.TypeBase64 = "base64"` (appended to `knownTypes`), `func policy.DecodeBase64(v string) (string, bool)`, `aegolith.TypeBase64`.

**Rules:** CR and LF are ignored; the alphabet is standard (`+/`) or URL-safe (`-_`), never both; padding is optional but must be correct when present; any other byte fails. The empty string is valid. `Validate` requires a JSON string, `withinRunes(value, spec.MaxLen)` on the encoded value, and a successful decode. In `typed`, a `base64` value is decoded and passed to `s.scan(loc, field, decoded)`; the encoded text is not scanned.

- [ ] **Step 1: Write the failing tests.**
  - `TestDecodeBase64` (table): `""`→ok `""`; `aGVsbG8=`→`hello`; `aGVsbG8`→`hello`; `aGVs\r\nbG8=`→`hello`; `-_8`→ok bytes `\xfb\xff`; `+/8=`→ok; rejects `+_8`, `aGVsbG8==`, `aGVsbG8=x`, `aGVs bG8=`, `aGVsbG8*`, `a`.
  - `TestValidateBase64`: `MaxLen: 8` accepts `aGVsbG8=` and rejects `aGVsbG8gd29ybGQ=`; `isString=false` rejects.
  - `TestBase64FieldIsDecodedAndScanned` (engine): route `POST /x` with JSON, query and form fields `data` of type `base64`, enforce; encode `1' UNION SELECT password FROM users--` in the test with `base64.StdEncoding`: assert block with `AEG-SQLI-001` on `body.data`, `query.data`, `form.data`.
  - `TestBase64FieldLegitimateText`: encoded multi-line note `"Leave at the desk.\nCall first, thanks."`, padded, unpadded and URL-safe: assert allow, no match.
  - `TestBase64FieldInvalidValue`: `not base64!!` on a declared field: assert `AEG-SCHEMA-001`.
  - `TestStringFieldIsNotDecoded`: the same encoded attack on a `text` field passes (behaviour unchanged).
  - `TestBase64ExclusionApplies`: an exclusion for `AEG-SQLI-*` on `body.data` allows the encoded attack.
- [ ] **Step 2:** `go test ./internal/policy/ ./internal/engine/ -run Base64 -count=1` — fails to compile (`DecodeBase64` undefined), then fails on behaviour.
- [ ] **Step 3:** Implement. A linear single pass or the `encoding/base64` decoders both do; `TestValidateLinearTime` must cover the new type.
- [ ] **Step 4:** Re-run (pass), `make ci` (exit 0).
- [ ] **Step 5:** Update docs.
- [ ] **Step 6:** Commit `feat: add a base64 field type that scans the decoded value` and push.

### Task 3: Trailing-slash template gap

**Files:**
- Modify: `internal/engine/inputs.go` (`declaredLiteral` and the two comments describing the gap)
- Test: `internal/engine/scanner_route_test.go`
- Modify docs: `docs/threat-model.md` (remove the entry from known gaps), `CHANGELOG.md`, and any other text found by searching the repo for "trailing slash"

**Interfaces:** none new.

- [ ] **Step 1: Write the failing test** `TestSlashTemplateRequestedWithoutSlash`: routes `GET /actuator/health/` and `GET /api/v1/hubs/:id/actuator/health/`, monitor mode. `/actuator/health` and `/api/v1/hubs/7/actuator/health` must report a scanner rule (`scannerRules` non-empty); `/actuator/health/` and `/api/v1/hubs/7/actuator/health/` report none. Check the template `/` and request `/` stays unchanged.
- [ ] **Step 2:** `go test ./internal/engine/ -run 'SlashTemplate|DeclaredRoute' -count=1` — the new test fails on the two slashless paths.
- [ ] **Step 3:** In `declaredLiteral`, return nil when the template is longer than `/`, ends in `/`, and the raw path does not.
- [ ] **Step 4:** Re-run (pass), `make ci` (exit 0).
- [ ] **Step 5:** Update docs and comments.
- [ ] **Step 6:** Commit `fix: do not excuse a slash template requested without its slash` and push.
