// Package fiberv2 is the Fiber v2 adapter for Aegolith: a middleware that
// inspects each request and answers 403 when the firewall blocks it.
package fiberv2

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/http"
	"net/textproto"
	"strings"

	"github.com/ergasterion-dev/aegolith"
	"github.com/gofiber/fiber/v2"
)

// Config tunes the middleware. Firewall should be set; the rest is optional.
type Config struct {
	// Firewall inspects the requests. A nil Firewall does not panic: every
	// request is allowed (the engine fails open and reports an internal
	// error), so OnDecision is still called once per request with
	// Decision.Err set. Always check the error returned by aegolith.New.
	Firewall *aegolith.Firewall
	// OnDecision is called for every blocked or monitored request and for
	// any decision carrying an internal error (never for a clean allow),
	// before a block response is written. A panic in the hook is recovered
	// and does not affect the request. Everything in the *aegolith.Request is
	// a private copy, safe to keep after the handler returns; treat it as
	// read-only.
	OnDecision func(*aegolith.Request, aegolith.Decision)
	// BlockHandler answers a blocked request. Default: 403 with the JSON
	// body {"error":"request blocked","request_id":"<id>"}.
	BlockHandler fiber.Handler
	// Next, if it returns true, skips inspection for that request.
	Next func(*fiber.Ctx) bool
	// RequestID returns the id put in the default block body. Default: a
	// safe incoming X-Request-Id, else a random 16 hex character id.
	RequestID func(*fiber.Ctx) string
}

const maxRequestIDLen = 64

// New returns a Fiber middleware that inspects each request with
// cfg.Firewall.
//
// fasthttp buffers are reused once the handler returns, so every string and
// byte slice given to the engine, the hook and the logs is a copy.
//
// Body: the engine inspects what the handler would see. c.Body() applies the
// request's Content-Encoding (gzip, deflate, br), so a compressed attack body
// is inspected decompressed. At most Limits().MaxBodyBytes+1 bytes of it are
// copied for inspection; a longer body makes the engine raise AEG-PROTO-003 on
// that prefix. The handler still sees the complete, unmodified body.
// Fiber/fasthttp itself inflates the whole body on c.Body(); bound that with
// fiber.Config.BodyLimit, which caps the compressed size.
//
// fasthttp does not neutralise the Transfer-Encoding/Content-Length
// smuggling variants the way net/http does, so the AEG-PROTO smuggling rules
// matter chiefly here. The header set the engine sees is built from the raw
// request headers with duplicates preserved; see the package tests for what
// fasthttp itself already rejects or rewrites before the middleware runs.
//
// Internal errors follow the firewall's fail-open or fail-closed setting; a
// panic in the inspection step never reaches the host. Panics in later
// handlers (c.Next) are not touched.
func New(cfg Config) fiber.Handler {
	maxBody := cfg.Firewall.Limits().MaxBodyBytes
	if maxBody == math.MaxInt64 {
		maxBody = math.MaxInt64 - 1 // keep maxBody+1 from overflowing
	}
	return func(c *fiber.Ctx) error {
		if cfg.Next != nil && cfg.Next(c) {
			return c.Next()
		}
		ar, dec, ok := inspect(cfg.Firewall, c, maxBody)
		if !ok {
			// Inspection itself panicked.
			if cfg.Firewall.FailOpen() {
				return c.Next()
			}
			return block(c, cfg)
		}
		if dec.Action != aegolith.ActionAllow || dec.Monitored || dec.Err != nil {
			callHook(cfg.OnDecision, ar, dec)
		}
		if dec.Action == aegolith.ActionBlock {
			return block(c, cfg)
		}
		return c.Next()
	}
}

// inspect builds the engine request from copies of the fasthttp data and
// inspects it. ok is false if anything in that step panicked.
func inspect(fw *aegolith.Firewall, c *fiber.Ctx, maxBody int64) (ar *aegolith.Request, dec aegolith.Decision, ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	uri := c.Request().URI()
	ar = &aegolith.Request{
		Method:     strings.Clone(c.Method()),
		RawPath:    string(uri.PathOriginal()),
		RawQuery:   string(uri.QueryString()),
		RemoteAddr: strings.Clone(c.IP()),
		Header:     engineHeader(c),
		Body:       inspectBody(c, maxBody),
		// Fiber routes case-insensitively unless CaseSensitive is set, so
		// "/API/v1/x" reaches the "/api/v1/x" handler; match the route
		// policy the same way.
		CaseInsensitiveRoutes: !c.App().Config().CaseSensitive,
	}
	return ar, fw.Inspect(ar), true
}

// engineHeader copies every raw request header, keeping duplicates in their
// original order, and adds Host and Content-Length when fasthttp keeps them
// out of VisitAll. It never invents a Content-Length.
func engineHeader(c *fiber.Ctx) http.Header {
	h := http.Header{}
	rh := &c.Request().Header
	rh.VisitAll(func(k, v []byte) {
		h.Add(textproto.CanonicalMIMEHeaderKey(string(k)), string(v))
	})
	if h.Get("Host") == "" {
		if host := c.Hostname(); host != "" {
			h.Set("Host", strings.Clone(host))
		}
	}
	if _, has := h["Content-Length"]; !has {
		if cl := rh.Peek("Content-Length"); len(cl) > 0 {
			h.Set("Content-Length", string(cl))
		}
	}
	return h
}

// inspectBody returns a copy of at most maxBody+1 bytes of what the handler
// would see from c.Body().
func inspectBody(c *fiber.Ctx, maxBody int64) []byte {
	b := c.Body()
	if len(b) == 0 {
		return nil
	}
	if int64(len(b)) > maxBody+1 {
		b = b[:maxBody+1]
	}
	return append([]byte(nil), b...)
}

func callHook(hook func(*aegolith.Request, aegolith.Decision), r *aegolith.Request, d aegolith.Decision) {
	if hook == nil {
		return
	}
	defer func() { _ = recover() }()
	hook(r, d)
}

func block(c *fiber.Ctx, cfg Config) error {
	if cfg.BlockHandler != nil {
		return cfg.BlockHandler(c)
	}
	body, _ := json.Marshal(struct {
		Error     string `json:"error"`
		RequestID string `json:"request_id"`
	}{"request blocked", requestID(c, cfg)})
	c.Status(fiber.StatusForbidden)
	c.Set(fiber.HeaderContentType, "application/json")
	return c.Send(append(body, '\n'))
}

func requestID(c *fiber.Ctx, cfg Config) string {
	if cfg.RequestID != nil {
		if id := safeCall(cfg.RequestID, c); id != "" {
			return id
		}
	}
	if id := c.Get("X-Request-Id"); validID(id) {
		return strings.Clone(id)
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(b[:])
}

func safeCall(f func(*fiber.Ctx) string, c *fiber.Ctx) (id string) {
	defer func() {
		if recover() != nil {
			id = ""
		}
	}()
	return f(c)
}

func validID(s string) bool {
	if s == "" || len(s) > maxRequestIDLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}
