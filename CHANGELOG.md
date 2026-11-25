# Changelog

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
