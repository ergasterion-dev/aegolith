# aegolith Fiber v2 adapter

A Fiber v2 middleware for [Aegolith](../../README.md). It inspects each
request and answers `403` with `{"error":"request blocked","request_id":"<id>"}`
when the firewall blocks it. This is a separate Go module so that the core
module stays free of Fiber.

## Install

```sh
go get github.com/ergasterion-dev/aegolith/adapters/fiberv2@v0.1.0-alpha.6
```

## Usage

```go
fw, err := aegolith.New(aegolith.Config{Mode: aegolith.ModeMonitor})
if err != nil {
	log.Fatal(err) // invalid configuration is reported at startup
}

app := fiber.New()
app.Use(fiberv2.New(fiberv2.Config{
	Firewall:   fw,
	OnDecision: httpwaf.SlogHook(slog.Default()), // from .../aegolith/httpwaf
	Next:       func(c *fiber.Ctx) bool { return c.Path() == "/healthz" },
}))
```

This is `ExampleNew` in [`example_test.go`](example_test.go) in monitor mode;
the example itself enforces and is compiled and run as a test.

`Config` fields: `Firewall`, `OnDecision` (called for blocked and monitored
requests and for decisions carrying an internal error, never for a clean
allow; panics in it are recovered), `BlockHandler` (custom `fiber.Handler` for
blocked requests), `Next` (skip inspection) and `RequestID` (id for the block
body; default is a safe `X-Request-Id` of at most 64 `[A-Za-z0-9._-]` bytes,
else 16 random hex characters).

A nil `Firewall` does not panic: requests pass through and `OnDecision` is
called with `Decision.Err` set. Internal errors follow `Config.FailOpen` of the
firewall.

## Route matching and letter case

Fiber routes case-insensitively unless `fiber.Config{CaseSensitive: true}` is
set, so `/API/v1/cart/items` reaches the `/api/v1/cart/items` handler. The
middleware reads `c.App().Config().CaseSensitive` and, when it is false,
matches the literal segments of your route policies case-insensitively too
(parameter values keep their case). Without this, a case variant of a path
would be an unknown route and escape the route's typed fields and
`unknown_fields: block`. Nothing to configure. Write templates in lower case:
under folding the most specific template wins (a literal beats a parameter,
which beats `*`), and of templates that differ only in letter case the first
declared wins, whereas Fiber serves the first registered handler. (Core
`v0.1.0-alpha.1` tried the exact-case template first instead.)

## Declared routes and scanner path rules (core v0.1.0-alpha.6)

From core `v0.1.0-alpha.6`, a scanner probe-path match (`AEG-SCANNER-002`,
`AEG-SCANNER-003`) is not reported when the matched text lies wholly in
literal segments of a declared route the request matched, so a declared
`GET /api/v1/stores/:id/actuator/health` is no longer blocked as an actuator
probe. Text in a `:name` or `*` segment still counts. Under Fiber's default
case-insensitive routing another letter case is excused too. Two forms excuse
nothing, because Fiber settings change which handler serves them: a trailing
slash the template does not have (without `StrictRouting` Fiber serves it
with the same handler, so such a health check stays blocked) and `%2F` in a
parameter or wildcard segment (`UnescapePath` splits on it). Not every such
form is covered: a declared template that ends in `/`, requested without that
slash, is excused, and with `StrictRouting` a template without parameters is
then served by a later `:name`, `*` or catch-all handler, if there is one (see
[known gaps](../../docs/threat-model.md#known-gaps-found-in-the-alpha6-review)).
If that could happen, register the route and declare its template without the
final slash. See the
[threat model](../../docs/threat-model.md#changes-in-alpha6-and-what-they-cost)
for this and every other change in alpha.6.

## Body inspection

The engine inspects what the handler sees: `c.Body()`, which applies
`Content-Encoding` (`gzip`, `deflate`, `br`, also stacked such as
`gzip, gzip`), so a compressed attack body is inspected decompressed. A list
that starts with a coding Fiber does not know (`identity, gzip`) gives an
empty `c.Body()` for both the engine and your handler. Codings Fiber does not
decode (`x-gzip`, upper-case `GZIP`, `zstd`) stay compressed: the engine sees
binary data and normally blocks it (`AEG-LFI-001`). A handler that decodes
`c.Request().Body()` itself sees data Aegolith did not. For an API, reject
request `Content-Encoding` other than `identity` before this middleware.

**Cap the body.** Up to `2 x Limits.MaxBodyBytes+1` bytes are copied for
inspection (default 1 MiB, so 2 MiB+1), matching what the engine inspects of
an over-cap body. A body over `MaxBodyBytes` raises `AEG-PROTO-003`, which
blocks by default and stops the inspection there, so enforce mode is
unaffected and a padded body is refused. (Core `v0.1.0-alpha.1` only monitored
it; this adapter requires core `v0.1.0-alpha.6` or later.)
If you set it back to monitor, an attack placed after `2 x MaxBodyBytes` of
padding reaches the handler. Fiber's default `BodyLimit` (4 MiB) is larger than `max_body_bytes`,
so set `fiber.Config{BodyLimit: ...}` at or below it as well.
`BodyLimit` caps the compressed size; fasthttp inflates the whole body on
`c.Body()`, so it is also your bound on decompression.

Since alpha.4 the copy is always `2 x MaxBodyBytes+1` for an over-cap body, in
enforce mode too (one extra copy of at most `MaxBodyBytes`), and monitor mode
inspects up to that size. A JSON or multipart body cut only by the cap does
not raise `AEG-PROTO-020` (this adapter requires core alpha.6 or later, which has
that fix).

The handler still receives the complete, unmodified body.

All strings and byte slices given to the engine and your hook are copies;
fasthttp buffers are reused after the handler returns.

## net/http vs fasthttp and request smuggling

Neither server hands the middleware the raw header block. net/http rejects or
rewrites the classic Transfer-Encoding/Content-Length variants before the
handler runs. Fasthttp normalises them too (the adapter tests record the exact
behaviour): `Transfer-Encoding: chunked` together with `Content-Length` leaves
only `Transfer-Encoding`, duplicate `Content-Length` collapses to the last
value, duplicate `Transfer-Encoding` to the first, and an unknown
`Transfer-Encoding` such as `xchunked` never reaches the handler. The
`AEG-PROTO` smuggling rules therefore act mainly as a backstop and as
defence in depth behind proxies that forward such headers differently.
