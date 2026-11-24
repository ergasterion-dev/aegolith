# aegolith Fiber v2 adapter

A Fiber v2 middleware for [Aegolith](../../README.md). It inspects each
request and answers `403` with `{"error":"request blocked","request_id":"<id>"}`
when the firewall blocks it. This is a separate Go module so that the core
module stays free of Fiber.

## Install

```sh
go get github.com/ergasterion-dev/aegolith/adapters/fiberv2
```

During development of the repository `go.mod` carries a
`replace github.com/ergasterion-dev/aegolith => ../..` directive. It is
removed at release, when the core module is tagged and required by version.

## Usage

```go
fw, err := aegolith.New(aegolith.Config{})
if err != nil {
	log.Fatal(err) // invalid configuration is reported at startup
}

app := fiber.New()
app.Use(fiberv2.New(fiberv2.Config{
	Firewall:   fw,
	OnDecision: httpwaf.SlogHook(slog.Default()), // from .../aegolith/httpwaf
	Next: func(c *fiber.Ctx) bool { return c.Path() == "/healthz" },
}))
```

`Config` fields: `Firewall`, `OnDecision` (called for blocked and monitored
requests and for decisions carrying an internal error, never for a clean
allow; panics in it are recovered), `BlockHandler` (custom `fiber.Handler` for
blocked requests), `Next` (skip inspection) and `RequestID` (id for the block
body; default is a safe `X-Request-Id` of at most 64 `[A-Za-z0-9._-]` bytes,
else 16 random hex characters).

A nil `Firewall` does not panic: requests pass through and `OnDecision` is
called with `Decision.Err` set. Internal errors follow `Config.FailOpen` of the
firewall.

## Body inspection

The engine inspects what the handler sees: `c.Body()`, which applies
`Content-Encoding` (gzip, deflate, br), so a compressed attack body is
inspected decompressed. At most `Limits.MaxBodyBytes+1` bytes are copied; a
longer body makes the engine report `AEG-PROTO-003` (monitor only) on that
prefix. The handler still receives the complete, unmodified body. Fasthttp
inflates the whole body on `c.Body()`, so bound compressed uploads with
`fiber.Config.BodyLimit`.

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
