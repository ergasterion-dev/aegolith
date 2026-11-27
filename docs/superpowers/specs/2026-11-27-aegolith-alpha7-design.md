# Aegolith alpha.7 design

Date: 2026-11-27. Status: approved in conversation (the maintainer delegated the open choices).

## Intent

Catch more attacks without blocking more legitimate requests, and show it with the WAF bench. A false positive stays worse than a missed probe.

## Goals

1. No request body that can reach a handler goes uninspected just because its content type was allowed.
2. A declared field can say it carries base64 text, so the detectors judge the decoded value.
3. The attack rules catch more of the development and baseline cases in places that are already inspected, with no new development or baseline false positive.
4. Close the alpha.6 gap where a declared template ending in `/`, requested without it, excuses the scanner path rules.

## Non-goals

- Decoding base64 automatically, or outside declared fields.
- Changing which headers are inspected by default.
- Changing the default content-type allow-list.
- Inspecting binary bodies or multipart file parts.

## Anti-goals

- A number that rises because rules were fitted to held-out cases. Rule work uses development and baseline cases only.
- Becoming a CRS clone.
- Spending latency on requests that did not ask for a feature.

## Approaches

### Base64

| Approach | Trade-off | Verdict |
|---|---|---|
| No decoding | No risk, the attacks stay missed | rejected |
| `base64` and `base64url` field types | Fits route typing, no guessing; does not change a run without a policy | **chosen** |
| Decode anything that looks like base64 | More detections without a policy; latency, and false positives on tokens and identifiers that the current test traffic cannot measure | rejected |

### Bodies of other content types

| Approach | Trade-off | Verdict |
|---|---|---|
| Refuse to start when an unparsed type is allowed | Breaks working configurations | rejected |
| Scan only a fixed list of textual types | A type nobody listed stays uninspected | rejected |
| Scan every type as text except a fixed list of binary types | A new false positive is possible on an allowed textual type | **chosen** |

## Behaviour

### Bodies

By media type, in this order:

1. JSON (`application/json`, `+json`): walked, as before.
2. `application/x-www-form-urlencoded`, `multipart/*`: parsed, as before.
3. Binary: `image/*`, `audio/*`, `video/*`, `font/*`, `model/*` (not `+xml`), `application/grpc*`, the OpenXML and OpenDocument prefixes (under the OpenDocument prefix, a type ending `+xml` or `-flat-xml` is XML), the suffixes `+zip`, `+gzip`, `+cbor` and `+der`, and a fixed list of exact types (in the threat model): not inspected. `image/svg+xml` is in this group.
4. XML (`application/xml`, `text/xml`, `+xml`, OpenDocument `-flat-xml`): read by value, with the XXE rule on the raw body, whether the type was allowed by `allow_xml` or by `allowed_content_types`.
5. Everything else, including a missing content type: scanned as text.

In the XML group, the XXE rule reads the raw body in windows. The body is tokenized with `encoding/xml` (strict) only with no declared charset, UTF-8, or an ASCII-compatible charset (ISO-8859-*, Latin-1, Windows-125x, US-ASCII, Shift_JIS, EUC-JP, EUC-KR, GB2312, GBK, GB18030, Big5, KOI8-R, KOI8-U, any case), which is read byte by byte (each byte becomes the code point of the same value). Any other declared charset, and a namespace prefix bound to `xmlns` or `""`, take the malformed fallback. Every text detector reads, on field `body`: character data (adjacent runs, CDATA included and runs separated only by comments or processing instructions, joined into one value), attribute values, and the content of a processing instruction other than the leading declaration (target `php` in any case rebuilt as `<?php ...?>`). An element whose local name is `script` (any ASCII case), or that is in the XHTML or SVG namespace, is also read as its rebuilt start tag, which carries its attribute values. Element and attribute names, namespace declarations, comments, directives and the leading declaration (which must have the XML shape: version, then optionally encoding, then optionally standalone) are not read. On a tokenizer error `AEG-PROTO-020`, on nesting deeper than `MaxDepth` `AEG-PROTO-010`, and at the unexpected end of a body cut at the inspection limit nothing; in all three cases the raw body is then scanned in windows. More values than `MaxFields` report `AEG-PROTO-010` once and are still read.

Known false positives: an element named `script`, an `svg` element in the SVG namespace, XHTML elements libinjection holds dangerous (`style`, `link`, `meta`) and a `style` attribute on a rendered element match the XSS rule through the rebuilt tag; escaped HTML in text (a feed's `&lt;p style=...&gt;`) is read unescaped, as in a JSON string, and matches it; an XML body that does not parse is scanned raw, where ordinary markup can match it. Accepted misses: attacks in comments, element or attribute names and namespace declarations, text split across child elements, and a payload that is an attack only once decoded from a multi-byte or non-Latin charset. Cost: the worst XML shapes read every value and then fail late, paying the full raw rescan; it is kept.

In enforce mode a refused content type still blocks before the body is read, so the default configuration behaves as before.

Accepted miss: with `AEG-PROTO-002` switched off or excluded, a body declared as a binary type is not inspected even if the handler parses it.

### `base64` and `base64url` field types

- `base64` accepts the standard alphabet (`+`, `/`) only, `base64url` the URL-safe alphabet (`-`, `_`) only. Each policy field states the alphabet its handler decodes; the handler of a `base64url` field must decode with a URL-safe decoder.
- One type for both alphabets was rejected: standard decoders that skip unknown characters (Python `base64.b64decode` by default, Ruby `Base64.decode64`) drop `-` and `_`, so a value judged as URL-safe could hide an attack from the firewall that such a handler reads. Scanning a second reading of each value was rejected too: it turns legitimate URL-safe values into binary noise. Each value is decoded once.
- Both types: padded or unpadded, with CR and LF ignored. The other alphabet, other whitespace and wrong padding are `AEG-SCHEMA-001`.
- `max_len` bounds the encoded value.
- The decoded value is judged by the detectors that read a JSON body value (`detect.ScanText`), in every location; matches and exclusions carry the location and field it was sent in. In the query string this differs from a `text` value: decoded text holds real line breaks, so the query-only command rule would block ordinary multi-line text.
- Meant for base64-encoded text. Binary content would be scanned as text.

## Done when

Development detection is up, development and baseline false positives are not, `make ci` and the latency budget pass, a new bench report is published unedited, and alpha.7 is tagged by the maintainer.

## Left to the builder

Names of unexported helpers, test layout, and wording of documentation.

## Open follow-ups (not in the first plan)

- Attack-rule improvements: planned after the missed development cases are analysed.
- A `}` inside a string closing a `#{` read.
- Route-priority desync, and the latency regression against alpha.5 (needs a quiet machine).
