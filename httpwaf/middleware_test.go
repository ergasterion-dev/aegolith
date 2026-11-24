package httpwaf

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ergasterion-dev/aegolith"
)

func newFW(t *testing.T, cfg aegolith.Config) *aegolith.Firewall {
	t.Helper()
	fw, err := aegolith.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return fw
}

const sqliQuery = "/items?id=1%27%20OR%20%271%27%3D%271"

func TestMiddlewareBlocks(t *testing.T) {
	var called, hooked atomic.Int32
	h := Middleware(newFW(t, aegolith.Config{}), Options{
		OnDecision: func(*aegolith.Request, aegolith.Decision) { hooked.Add(1) },
		RequestID:  func(*http.Request) string { return "req-1" },
	})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called.Add(1) }))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", sqliQuery, nil))

	if rec.Code != 403 || called.Load() != 0 || hooked.Load() != 1 {
		t.Fatalf("code=%d called=%d hooked=%d", rec.Code, called.Load(), hooked.Load())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type %q", ct)
	}
	if got := rec.Body.String(); strings.TrimSpace(got) != `{"error":"request blocked","request_id":"req-1"}` {
		t.Fatalf("body %q", got)
	}
	if strings.Contains(rec.Body.String(), "AEG-") {
		t.Fatal("rule id leaked")
	}
}

func TestMiddlewareCustomBlockHandler(t *testing.T) {
	h := Middleware(newFW(t, aegolith.Config{}), Options{
		BlockHandler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(451) }),
	})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("next called") }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", sqliQuery, nil))
	if rec.Code != 451 {
		t.Fatalf("code %d", rec.Code)
	}
}

func TestMiddlewareAllows(t *testing.T) {
	var hooked atomic.Int32
	h := Middleware(newFW(t, aegolith.Config{}), Options{
		OnDecision: func(*aegolith.Request, aegolith.Decision) { hooked.Add(1) },
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/items?page=2", nil))
	if rec.Code != 204 {
		t.Fatalf("code %d", rec.Code)
	}
	if hooked.Load() != 0 {
		t.Fatalf("hook called for clean allow")
	}
}

func jsonBody(n int) []byte {
	b := bytes.Repeat([]byte("abcdefghij"), n/10+1)[:n]
	copy(b, `{"note":"`)
	b[n-2], b[n-1] = '"', '}'
	return b
}

func TestMiddlewareBodyRestored(t *testing.T) {
	const limit = 1 << 20
	for name, size := range map[string]int{"small": 1000, "exact-limit": limit, "limit+1": limit + 1, "2MiB": 2 << 20} {
		t.Run(name, func(t *testing.T) {
			want := jsonBody(size)
			var got []byte
			var rerr error
			h := Middleware(newFW(t, aegolith.Config{Mode: aegolith.ModeMonitor}), Options{})(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					got, rerr = io.ReadAll(r.Body)
					rerr = errors.Join(rerr, r.Body.Close())
				}))
			req := httptest.NewRequest("POST", "/upload", bytes.NewReader(want))
			req.Header.Set("Content-Type", "application/json")
			h.ServeHTTP(httptest.NewRecorder(), req)
			if rerr != nil || !bytes.Equal(got, want) {
				t.Fatalf("body mismatch: err=%v len(got)=%d len(want)=%d", rerr, len(got), len(want))
			}
		})
	}
}

type countingBody struct {
	r      io.Reader
	n      atomic.Int64
	closed atomic.Bool
}

func (c *countingBody) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}
func (c *countingBody) Close() error { c.closed.Store(true); return nil }

func TestMiddlewareReadsAtMostLimitPlusOneAndKeepsClose(t *testing.T) {
	cb := &countingBody{r: bytes.NewReader(jsonBody(3 << 20))}
	inspected := -1
	h := Middleware(newFW(t, aegolith.Config{Mode: aegolith.ModeMonitor}), Options{
		OnDecision: func(r *aegolith.Request, _ aegolith.Decision) {
			inspected = len(r.Body)
		},
	})(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if cb.n.Load() > 1<<20+1 {
			t.Errorf("middleware consumed %d bytes", cb.n.Load())
		}
		_ = r.Body.Close()
	}))
	req := httptest.NewRequest("POST", "/u", nil)
	req.Body = cb
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if !cb.closed.Load() {
		t.Fatal("original Close not preserved")
	}
	if inspected != 1<<20+1 {
		t.Fatalf("hook ran=%v, inspected %d bytes", inspected >= 0, inspected)
	}
}

type errBody struct {
	data []byte
	err  error
	pos  int
}

func (e *errBody) Read(p []byte) (int, error) {
	if e.pos < len(e.data) {
		n := copy(p, e.data[e.pos:])
		e.pos += n
		return n, nil
	}
	return 0, e.err
}
func (e *errBody) Close() error { return nil }

func TestMiddlewareBodyReadError(t *testing.T) {
	boom := errors.New("boom")
	var got []byte
	var rerr error
	h := Middleware(newFW(t, aegolith.Config{}), Options{})(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, rerr = io.ReadAll(r.Body)
	}))
	req := httptest.NewRequest("POST", "/u", nil)
	req.Body = &errBody{data: []byte(`{"a":1`), err: boom}
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if string(got) != `{"a":1` || !errors.Is(rerr, boom) {
		t.Fatalf("got %q err %v", got, rerr)
	}
}

func TestMiddlewareMonitorCallsHook(t *testing.T) {
	var dec aegolith.Decision
	var hooked int
	var nextCalled bool
	h := Middleware(newFW(t, aegolith.Config{Mode: aegolith.ModeMonitor}), Options{
		OnDecision: func(_ *aegolith.Request, d aegolith.Decision) { hooked++; dec = d },
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { nextCalled = true }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", sqliQuery, nil))
	if !nextCalled || rec.Code != 200 || hooked != 1 || !dec.Monitored || len(dec.Matches) == 0 {
		t.Fatalf("next=%v code=%d hooked=%d dec=%+v", nextCalled, rec.Code, hooked, dec)
	}
}

func TestEngineHeaderBuildingFromHandBuiltRequest(t *testing.T) {
	var seen http.Header
	var method, rawPath string
	h := Middleware(newFW(t, aegolith.Config{}), Options{
		OnDecision: func(r *aegolith.Request, _ aegolith.Decision) {
			seen = r.Header
			method = r.Method
			rawPath = r.RawPath
		},
	})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequest("POST", "/a%2Fb", strings.NewReader("x"))
	req.Header.Set("Content-Type", "application/json")
	req.TransferEncoding = []string{"chunked"}
	req.ContentLength = 1
	req.Host = "example.test"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("TE+CL request should be blocked by smuggling rule, got %d", rec.Code)
	}
	if seen.Get("Transfer-Encoding") != "chunked" || seen.Get("Content-Length") != "1" || seen.Get("Host") != "example.test" {
		t.Fatalf("headers %v", seen)
	}
	if method != "POST" || rawPath != "/a%2Fb" {
		t.Fatalf("method %q rawpath %q", method, rawPath)
	}
	if _, ok := req.Header["Transfer-Encoding"]; ok {
		t.Fatal("original request headers mutated")
	}
}

func TestRequestIDSanitised(t *testing.T) {
	cases := map[string]bool{
		"abc-123_X.y":           true,
		"":                      false,
		`a"b`:                   false,
		"a b":                   false,
		"x\ny":                  false,
		strings.Repeat("a", 64): true,
		strings.Repeat("a", 65): false,
		"</script>":             false,
		"é":                     false,
	}
	for in, keep := range cases {
		req := httptest.NewRequest("GET", "/", nil)
		if in != "" {
			req.Header["X-Request-Id"] = []string{in}
		}
		got := requestID(req, Options{})
		if keep && got != in {
			t.Errorf("%q: got %q", in, got)
		}
		if !keep && (got == in || len(got) != 16) {
			t.Errorf("%q: expected generated id, got %q", in, got)
		}
	}
	// opts.RequestID wins, and the 403 body stays valid JSON for hostile ids.
	h := Middleware(newFW(t, aegolith.Config{}), Options{RequestID: func(*http.Request) string { return "a\"</b>\n" }})(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", sqliQuery, nil))
	var m map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil || m["request_id"] != "a\"</b>\n" {
		t.Fatalf("body %q err %v", rec.Body.String(), err)
	}
}

func TestMiddlewareHookPanicDoesNotBreakServing(t *testing.T) {
	var next int
	h := Middleware(newFW(t, aegolith.Config{Mode: aegolith.ModeMonitor}), Options{
		OnDecision: func(*aegolith.Request, aegolith.Decision) { panic("bad hook") },
	})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { next++ }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", sqliQuery, nil))
	if next != 1 || rec.Code != 200 {
		t.Fatalf("next=%d code=%d", next, rec.Code)
	}
	// A panicking hook on a block still blocks.
	h = Middleware(newFW(t, aegolith.Config{}), Options{
		OnDecision: func(*aegolith.Request, aegolith.Decision) { panic("bad hook") },
	})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("next called") }))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", sqliQuery, nil))
	if rec.Code != 403 {
		t.Fatalf("code %d", rec.Code)
	}
}

func TestMiddlewareNextPanicPropagates(t *testing.T) {
	h := Middleware(newFW(t, aegolith.Config{}), Options{})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("app") }))
	defer func() {
		if recover() == nil {
			t.Fatal("handler panic must reach the host's own recovery")
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
}

func TestMiddlewareNilFirewallFailsOpen(t *testing.T) {
	var next int
	h := Middleware(nil, Options{})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { next++ }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", sqliQuery, nil))
	if next != 1 {
		t.Fatalf("next=%d code=%d", next, rec.Code)
	}
}

func TestMiddlewareConcurrent(t *testing.T) {
	var mu sync.Mutex
	var rules []string
	h := Middleware(newFW(t, aegolith.Config{}), Options{
		OnDecision: func(_ *aegolith.Request, d aegolith.Decision) {
			if d.Action != aegolith.ActionBlock {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			var ids []string
			for _, m := range d.Matches {
				ids = append(ids, m.RuleID)
			}
			rules = append(rules, strings.Join(ids, ","))
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := httptest.NewRecorder()
			if i%2 == 0 {
				h.ServeHTTP(rec, httptest.NewRequest("GET", sqliQuery, nil))
				if rec.Code != 403 {
					t.Errorf("code %d", rec.Code)
				}
				return
			}
			req := httptest.NewRequest("POST", "/x", bytes.NewReader(jsonBody(50000)))
			req.Header.Set("Content-Type", "application/json")
			h.ServeHTTP(rec, req)
			if rec.Code != 200 {
				t.Errorf("code %d", rec.Code)
			}
		}(i)
	}
	wg.Wait()
	if len(rules) != 16 {
		t.Fatalf("hook calls %d: %q", len(rules), rules)
	}
	for _, r := range rules {
		if r != rules[0] || r == "" {
			t.Fatalf("decisions differ: %q vs %q", r, rules[0])
		}
	}
}

// recHandler captures slog records.
type recHandler struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (h *recHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.recs = append(h.recs, r)
	return nil
}
func (h *recHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recHandler) WithGroup(string) slog.Handler      { return h }

func attrs(r slog.Record) map[string]slog.Value {
	m := map[string]slog.Value{}
	r.Attrs(func(a slog.Attr) bool { m[a.Key] = a.Value; return true })
	return m
}

func TestSlogHook(t *testing.T) {
	rh := &recHandler{}
	hook := SlogHook(slog.New(rh))

	run := func(mode aegolith.Mode, target string) {
		h := Middleware(newFW(t, aegolith.Config{Mode: mode}), Options{OnDecision: hook})(
			http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", target, nil))
	}
	run(aegolith.ModeEnforce, "/clean?page=1")
	if len(rh.recs) != 0 {
		t.Fatalf("clean allow logged: %d", len(rh.recs))
	}
	run(aegolith.ModeEnforce, sqliQuery)
	run(aegolith.ModeMonitor, sqliQuery)
	if len(rh.recs) != 2 {
		t.Fatalf("records %d", len(rh.recs))
	}
	if rh.recs[0].Level != slog.LevelWarn || rh.recs[1].Level != slog.LevelInfo {
		t.Fatalf("levels %v %v", rh.recs[0].Level, rh.recs[1].Level)
	}
	a := attrs(rh.recs[0])
	for _, k := range []string{"method", "path", "rules", "categories", "fields", "snippets"} {
		if _, ok := a[k]; !ok {
			t.Fatalf("missing attr %q in %v", k, a)
		}
	}
	if a["method"].String() != "GET" || a["path"].String() != "/items" {
		t.Fatalf("attrs %v", a)
	}
	if !strings.Contains(a["rules"].String(), "AEG-SQLI") {
		t.Fatalf("rules %v", a["rules"])
	}
	fields, snips := a["fields"].Any().([]string), a["snippets"].Any().([]string)
	if len(fields) == 0 || len(fields) != len(snips) || len(a["categories"].Any().([]string)) != len(fields) {
		t.Fatalf("attr shapes %v", a)
	}
	for i := range fields {
		if !strings.HasPrefix(fields[i], "query.") || snips[i] == "" || len(snips[i]) > 64 {
			t.Fatalf("field %q snippet %q", fields[i], snips[i])
		}
	}
}

func TestSlogHookNilLoggerUsesDefault(t *testing.T) {
	if SlogHook(nil) == nil {
		t.Fatal("nil hook")
	}
	SlogHook(nil)(&aegolith.Request{}, aegolith.Decision{}) // must not panic
}

// rawTCP sends raw bytes to a real net/http server wrapped by the middleware
// and returns the headers the engine saw (nil if the hook did not run), the
// response status and the body length the application read.
func rawTCP(t *testing.T, req string) (seen http.Header, status, bodyN int) {
	t.Helper()
	var mu sync.Mutex
	h := Middleware(newFW(t, aegolith.Config{Mode: aegolith.ModeMonitor}), Options{
		OnDecision: func(r *aegolith.Request, _ aegolith.Decision) { mu.Lock(); seen = r.Header; mu.Unlock() },
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodyN = len(b)
		mu.Unlock()
	}))
	s := httptest.NewServer(h)
	defer s.Close()
	c, err := net.Dial("tcp", s.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	mu.Lock()
	defer mu.Unlock()
	return seen, resp.StatusCode, bodyN
}

// Through a real server net/http neutralises TE.CL itself: Content-Length is
// dropped when Transfer-Encoding: chunked is present, so the engine sees only
// the Transfer-Encoding header (the smuggling rules matter for other servers).
func TestRealServerTransferEncodingContentLength(t *testing.T) {
	const pre = "POST /x HTTP/1.1\r\nHost: a\r\nContent-Type: application/json\r\nConnection: close\r\n"
	seen, status, n := rawTCP(t, pre+"Transfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n3\r\nabc\r\n0\r\n\r\n")
	if status != 200 || seen.Get("Transfer-Encoding") != "chunked" || seen.Get("Content-Length") != "" || n != 3 {
		t.Fatalf("status=%d seen=%v bodyN=%d", status, seen, n)
	}
	if _, status, _ := rawTCP(t, pre+"Transfer-Encoding: xchunked\r\n\r\n"); status != 501 {
		t.Fatalf("xchunked status %d", status)
	}
	if _, status, _ := rawTCP(t, pre+"Content-Length: 5\r\nContent-Length: 6\r\n\r\nabcdef"); status != 400 {
		t.Fatalf("duplicate CL status %d", status)
	}
}

func TestMiddlewareNoSyntheticContentLengthZero(t *testing.T) {
	var seen http.Header
	h := Middleware(newFW(t, aegolith.Config{}), Options{
		OnDecision: func(r *aegolith.Request, _ aegolith.Decision) { seen = r.Header },
	})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", sqliQuery, nil))
	if _, ok := seen["Content-Length"]; ok {
		t.Fatalf("synthetic Content-Length on bodyless request: %v", seen)
	}
}

func TestMiddlewareMaxInt64LimitNoOverflow(t *testing.T) {
	fw := newFW(t, aegolith.Config{Limits: aegolith.Limits{MaxBodyBytes: 1<<63 - 1}})
	var got []byte
	h := Middleware(fw, Options{})(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got, _ = io.ReadAll(r.Body) }))
	req := httptest.NewRequest("POST", "/x", strings.NewReader(`{"a":1}`))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if string(got) != `{"a":1}` {
		t.Fatalf("got %q", got)
	}
}

func TestMiddlewareHeadBlocks(t *testing.T) {
	h := Middleware(newFW(t, aegolith.Config{}), Options{})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("next called") }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("HEAD", sqliQuery, nil))
	if rec.Code != 403 {
		t.Fatalf("code %d", rec.Code)
	}
}

func TestMiddlewareHookOnInternalError(t *testing.T) {
	var hooked int
	var nilFW *aegolith.Firewall
	h := Middleware(nilFW, Options{
		OnDecision: func(_ *aegolith.Request, d aegolith.Decision) {
			hooked++
			if d.Err == nil {
				t.Error("expected Err")
			}
		},
	})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	if hooked != 1 {
		t.Fatalf("hooked %d", hooked)
	}
}

func TestSlogHookErrorLevelAndTruncation(t *testing.T) {
	rh := &recHandler{}
	hook := SlogHook(slog.New(rh))
	hook(&aegolith.Request{Method: "GET", RawPath: "/"}, aegolith.Decision{Err: errors.New("boom\nsecond line")})
	if len(rh.recs) != 1 || rh.recs[0].Level != slog.LevelError {
		t.Fatalf("recs %v", rh.recs)
	}
	e := attrs(rh.recs[0])["error"].String()
	if strings.Contains(e, "\n") || !strings.Contains(e, "boom") {
		t.Fatalf("error attr %q", e)
	}
	hook(&aegolith.Request{Method: "GET", RawPath: "/" + strings.Repeat("p", 500) + "?q=secret"}, aegolith.Decision{
		Action:  aegolith.ActionBlock,
		Matches: []aegolith.Match{{RuleID: "AEG-X", Category: aegolith.CatSQLi, Field: strings.Repeat("f", 300), Snippet: "snip"}},
	})
	a := attrs(rh.recs[1])
	if len(a["path"].String()) != 256 {
		t.Fatalf("path len %d", len(a["path"].String()))
	}
	if f := a["fields"].Any().([]string)[0]; len(f) != 128 {
		t.Fatalf("field len %d", len(f))
	}
}
