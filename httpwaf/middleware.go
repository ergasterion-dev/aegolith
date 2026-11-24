// Package httpwaf is the net/http adapter for Aegolith: a middleware that
// inspects each request and answers 403 when the firewall blocks it.
package httpwaf

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"strconv"

	"github.com/ergasterion-dev/aegolith"
)

// Options tunes the middleware. The zero value is valid.
type Options struct {
	// OnDecision is called for every blocked or monitored request and for
	// any decision carrying an internal error (never for a clean allow), before a block response is written. A panic in the
	// hook is recovered and does not affect the request.
	//
	// The *aegolith.Request passed to the hook (and to BlockHandler via
	// r.Body) shares the buffered body bytes without copying: treat them as
	// read-only.
	OnDecision func(*aegolith.Request, aegolith.Decision)
	// BlockHandler answers a blocked request. Default: 403 with the JSON
	// body {"error":"request blocked","request_id":"<id>"}.
	BlockHandler http.Handler
	// RequestID returns the id put in the default block body. Default: a
	// safe incoming X-Request-Id, else a random 16 hex character id.
	RequestID func(*http.Request) string
}

const maxRequestIDLen = 64

// Middleware returns a handler wrapper that inspects each request with fw.
//
// net/http neutralises the classic Transfer-Encoding/Content-Length
// smuggling variants itself (it drops Content-Length next to chunked and
// rejects malformed Transfer-Encoding or duplicate Content-Length with 4xx/501
// before any handler runs), so the AEG-PROTO smuggling rules matter chiefly
// for other servers such as fasthttp/Fiber.
//
// Inspecting the body means it is read before the decision, so an
// "Expect: 100-continue" request has its 100 sent before a block is decided.
//
// The request body is read up to Limits.MaxBodyBytes+1 bytes for inspection
// and then restored, so the next handler sees the complete original stream.
// Bytes past that limit are not inspected, and AEG-PROTO-003 (body over the
// limit) is monitor by default, so padding can push an attack out of sight:
// wrap the body in http.MaxBytesReader at or below MaxBodyBytes before this
// middleware, or set AEG-PROTO-003 to block in Config.RuleActions.
//
// net/http does not decode Content-Encoding and neither does this
// middleware: a compressed body is inspected as compressed bytes (normally
// blocked as AEG-LFI-001 for its NUL bytes). Put any request-decompression
// middleware before this one, not after it, or reject Content-Encoding other
// than identity.
// Internal errors follow the firewall's fail-open or fail-closed setting; a
// panic inside the inspection step never reaches the host. Panics in the
// next handler are not touched.
func Middleware(fw *aegolith.Firewall, opts Options) func(http.Handler) http.Handler {
	maxBody := fw.Limits().MaxBodyBytes
	if maxBody == math.MaxInt64 {
		maxBody = math.MaxInt64 - 1 // keep maxBody+1 from overflowing
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ar, dec, ok := inspect(fw, r, maxBody)
			if !ok {
				// Inspection itself panicked.
				if fw.FailOpen() {
					next.ServeHTTP(w, r)
					return
				}
				block(w, r, opts)
				return
			}
			if dec.Action != aegolith.ActionAllow || dec.Monitored || dec.Err != nil {
				callHook(opts.OnDecision, ar, dec)
			}
			if dec.Action == aegolith.ActionBlock {
				block(w, r, opts)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// inspect builds the engine request (restoring r.Body) and inspects it. ok
// is false if anything in that step panicked.
func inspect(fw *aegolith.Firewall, r *http.Request, maxBody int64) (ar *aegolith.Request, dec aegolith.Decision, ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	ar = &aegolith.Request{
		Method:     r.Method,
		RawPath:    r.URL.EscapedPath(),
		RawQuery:   r.URL.RawQuery,
		RemoteAddr: r.RemoteAddr,
		Header:     engineHeader(r),
		Body:       readBody(r, maxBody),
	}
	return ar, fw.Inspect(ar), true
}

// engineHeader clones r.Header and adds what net/http keeps elsewhere
// (Transfer-Encoding, Content-Length, Host), because the protocol checks
// read only Request.Header.
func engineHeader(r *http.Request) http.Header {
	h := r.Header.Clone()
	if h == nil {
		h = http.Header{}
	}
	if _, has := h["Transfer-Encoding"]; !has {
		for _, te := range r.TransferEncoding {
			h.Add("Transfer-Encoding", te)
		}
	}
	if r.ContentLength > 0 && h.Get("Content-Length") == "" {
		h.Set("Content-Length", strconv.FormatInt(r.ContentLength, 10))
	}
	if h.Get("Host") == "" && r.Host != "" {
		h.Set("Host", r.Host)
	}
	return h
}

// readBody reads at most maxBody+1 bytes of r.Body and replaces r.Body with
// the prefix followed by the unread rest, keeping the original Close. A read
// error is replayed after the prefix instead of being swallowed.
func readBody(r *http.Request, maxBody int64) []byte {
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	orig := r.Body
	limit := maxBody + 1
	var buf bytes.Buffer
	if r.ContentLength > 0 && r.ContentLength < limit {
		buf.Grow(int(r.ContentLength))
	}
	_, err := buf.ReadFrom(io.LimitReader(orig, limit))
	prefix := buf.Bytes()
	var rest io.Reader = orig
	if err != nil {
		rest = errReader{err}
	}
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(prefix), rest), orig}
	return prefix
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

func callHook(hook func(*aegolith.Request, aegolith.Decision), r *aegolith.Request, d aegolith.Decision) {
	if hook == nil {
		return
	}
	defer func() { _ = recover() }()
	hook(r, d)
}

func block(w http.ResponseWriter, r *http.Request, opts Options) {
	if opts.BlockHandler != nil {
		opts.BlockHandler.ServeHTTP(w, r)
		return
	}
	body, _ := json.Marshal(struct {
		Error     string `json:"error"`
		RequestID string `json:"request_id"`
	}{"request blocked", requestID(r, opts)})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(append(body, '\n'))
}

func requestID(r *http.Request, opts Options) string {
	if opts.RequestID != nil {
		if id := safeCall(opts.RequestID, r); id != "" {
			return id
		}
	}
	if id := r.Header.Get("X-Request-Id"); validID(id) {
		return id
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(b[:])
}

func safeCall(f func(*http.Request) string, r *http.Request) (id string) {
	defer func() {
		if recover() != nil {
			id = ""
		}
	}()
	return f(r)
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
