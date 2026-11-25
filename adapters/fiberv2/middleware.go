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
	"sync/atomic"

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
// Routes: Fiber matches routes case-insensitively unless
// fiber.Config.CaseSensitive is set, so the middleware asks the firewall to
// match literal route segments case-insensitively for each request in that
// case (see aegolith.Request.CaseInsensitiveRoutes).
//
// Body: the engine inspects what the handler would see. c.Body() applies the
// request's Content-Encoding (gzip, deflate, br), so a compressed attack body
// is inspected decompressed; codings Fiber does not decode (x-gzip, zstd)
// stay compressed. At most 2 x Limits().MaxBodyBytes+1 bytes of it are
// copied for inspection, matching the engine's inspection limit for an
// over-cap body (the extra byte tells it the body was cut). A body longer
// than MaxBodyBytes raises AEG-PROTO-003, which blocks by default and stops
// the inspection before the body is read, so enforce decisions do not
// change; when the rule does not block (monitor mode, or Config.RuleActions
// setting it to monitor), an attack placed after up to MaxBodyBytes of
// padding is still seen, and only what lies past 2 x MaxBodyBytes is not.
// Still set fiber.Config.BodyLimit at or below MaxBodyBytes. The handler
// still sees the complete, unmodified body.
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
	maxCopy := bodyCopyLimit(cfg.Firewall)
	folds := &routeFold{load: appFoldsRoutes}
	return func(c *fiber.Ctx) error {
		if cfg.Next != nil && cfg.Next(c) {
			return c.Next()
		}
		ar, dec, ok := inspect(cfg.Firewall, c, maxCopy, folds)
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
func inspect(fw *aegolith.Firewall, c *fiber.Ctx, maxCopy int64, folds *routeFold) (ar *aegolith.Request, dec aegolith.Decision, ok bool) {
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
		Body:       inspectBody(c, maxCopy),
		// Fiber routes case-insensitively unless CaseSensitive is set, so
		// "/API/v1/x" reaches the "/api/v1/x" handler; match the route
		// policy the same way.
		CaseInsensitiveRoutes: folds.get(c.App()),
	}
	return ar, fw.Inspect(ar), true
}

// routeFold caches, per middleware instance, whether the app routes
// case-insensitively. c.App().Config() copies the whole fiber.Config, so it
// is read once per app rather than on every request. The cache is keyed on
// the *fiber.App, so one handler mounted on two apps stays correct (the
// second app replaces the entry and is read again on a switch).
type routeFold struct {
	load  func(*fiber.App) bool
	cache atomic.Pointer[foldEntry]
}

type foldEntry struct {
	app   *fiber.App
	folds bool
}

func (f *routeFold) get(app *fiber.App) bool {
	if e := f.cache.Load(); e != nil && e.app == app {
		return e.folds
	}
	e := &foldEntry{app: app, folds: f.load(app)}
	f.cache.Store(e)
	return e.folds
}

// appFoldsRoutes reports whether app routes literal segments
// case-insensitively (Fiber's default unless CaseSensitive is set).
func appFoldsRoutes(app *fiber.App) bool { return !app.Config().CaseSensitive }

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

// bodyCopyLimit returns how many bytes of a request body to copy for
// inspection: the engine's limit for an over-cap body (2 x MaxBodyBytes)
// plus one byte that tells it the body was cut, guarded against overflow.
// It does not depend on the mode: Fiber already holds the whole body, so
// the cost is one bounded copy, and when AEG-PROTO-003 blocks the engine
// stops on it before the body is parsed, so enforce decisions are the same.
func bodyCopyLimit(fw *aegolith.Firewall) int64 {
	maxBody := fw.Limits().MaxBodyBytes
	if maxBody > (math.MaxInt64-1)/2 {
		return math.MaxInt64
	}
	return 2*maxBody + 1
}

// inspectBody returns a copy of at most maxCopy bytes of what the handler
// would see from c.Body().
func inspectBody(c *fiber.Ctx, maxCopy int64) []byte {
	b := c.Body()
	if len(b) == 0 {
		return nil
	}
	if int64(len(b)) > maxCopy {
		b = b[:maxCopy]
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
