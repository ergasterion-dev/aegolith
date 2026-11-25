package fiberv2

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ergasterion-dev/aegolith"
	"github.com/gofiber/fiber/v2"
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

// newApp mounts the middleware and a catch-all handler that echoes the body
// it sees and counts how often it ran.
func newApp(cfg Config, calls *atomic.Int32) *fiber.App {
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(New(cfg))
	app.All("/*", func(c *fiber.Ctx) error {
		if calls != nil {
			calls.Add(1)
		}
		return c.Send(c.Body())
	})
	return app
}

func do(t *testing.T, app *fiber.App, req *http.Request) (int, []byte, http.Header) {
	t.Helper()
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, resp.Header
}

func jsonBody(n int) []byte {
	var b bytes.Buffer
	b.WriteString(`{"items":[`)
	for b.Len() < n {
		b.WriteString(`"hello world",`)
	}
	b.WriteString(`"end"]}`)
	return b.Bytes()
}

func TestFiberBlocksSQLi(t *testing.T) {
	var calls, hooked atomic.Int32
	app := newApp(Config{
		Firewall:   newFW(t, aegolith.Config{}),
		OnDecision: func(*aegolith.Request, aegolith.Decision) { hooked.Add(1) },
		RequestID:  func(*fiber.Ctx) string { return "req-1" },
	}, &calls)
	code, body, h := do(t, app, httptest.NewRequest("GET", sqliQuery, nil))
	if code != 403 || calls.Load() != 0 || hooked.Load() != 1 {
		t.Fatalf("code=%d calls=%d hooked=%d", code, calls.Load(), hooked.Load())
	}
	if ct := h.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type %q", ct)
	}
	if strings.TrimSpace(string(body)) != `{"error":"request blocked","request_id":"req-1"}` {
		t.Fatalf("body %q", body)
	}
	if strings.Contains(string(body), "AEG-") {
		t.Fatal("rule id leaked")
	}
}

func TestFiberAllowsLegit(t *testing.T) {
	var calls, hooked atomic.Int32
	app := newApp(Config{
		Firewall:   newFW(t, aegolith.Config{}),
		OnDecision: func(*aegolith.Request, aegolith.Decision) { hooked.Add(1) },
	}, &calls)
	code, _, _ := do(t, app, httptest.NewRequest("GET", "/items?name=widget&page=2", nil))
	if code != 200 || calls.Load() != 1 || hooked.Load() != 0 {
		t.Fatalf("code=%d calls=%d hooked=%d", code, calls.Load(), hooked.Load())
	}
}

func TestFiberBlocksSQLiInBody(t *testing.T) {
	var calls atomic.Int32
	app := newApp(Config{Firewall: newFW(t, aegolith.Config{})}, &calls)
	req := httptest.NewRequest("POST", "/x", strings.NewReader(`{"q":"1' OR '1'='1"}`))
	req.Header.Set("Content-Type", "application/json")
	if code, _, _ := do(t, app, req); code != 403 || calls.Load() != 0 {
		t.Fatalf("code=%d calls=%d", code, calls.Load())
	}
}

func TestFiberBodyIntact(t *testing.T) {
	small := []byte(`{"name":"widget","qty":3}`)
	over := jsonBody(1<<20 + 4096) // larger than the 1 MiB default limit
	for name, body := range map[string][]byte{"small": small, "over-limit": over} {
		t.Run(name, func(t *testing.T) {
			var sawSize atomic.Int64
			var hooked atomic.Int32
			app := newApp(Config{
				Firewall: newFW(t, aegolith.Config{Mode: aegolith.ModeMonitor}),
				OnDecision: func(r *aegolith.Request, _ aegolith.Decision) {
					hooked.Add(1)
					sawSize.Store(int64(len(r.Body)))
				},
			}, nil)
			req := httptest.NewRequest("POST", "/x", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			code, got, _ := do(t, app, req)
			if code != 200 || !bytes.Equal(got, body) {
				t.Fatalf("code=%d len(got)=%d len(want)=%d", code, len(got), len(body))
			}
			switch name {
			case "over-limit":
				// Monitored (AEG-PROTO-003), so the hook must run exactly
				// once; in monitor the engine inspects up to 2 x limit, so
				// it gets the whole body.
				if hooked.Load() != 1 || sawSize.Load() != int64(len(body)) {
					t.Fatalf("hook calls=%d, engine got %d bytes, want 1 call and %d bytes", hooked.Load(), sawSize.Load(), len(body))
				}
			case "small":
				// A clean allow never reaches the hook.
				if hooked.Load() != 0 {
					t.Fatalf("hook called %d times for a clean request", hooked.Load())
				}
			}
		})
	}
}

func TestFiberNextSkips(t *testing.T) {
	var calls atomic.Int32
	app := newApp(Config{
		Firewall: newFW(t, aegolith.Config{}),
		Next:     func(c *fiber.Ctx) bool { return c.Path() == "/items" },
	}, &calls)
	code, _, _ := do(t, app, httptest.NewRequest("GET", sqliQuery, nil))
	if code != 200 || calls.Load() != 1 {
		t.Fatalf("code=%d calls=%d", code, calls.Load())
	}
}

func TestFiberCustomBlockHandler(t *testing.T) {
	app := newApp(Config{
		Firewall:     newFW(t, aegolith.Config{}),
		BlockHandler: func(c *fiber.Ctx) error { return c.SendStatus(451) },
	}, nil)
	if code, _, _ := do(t, app, httptest.NewRequest("GET", sqliQuery, nil)); code != 451 {
		t.Fatalf("code %d", code)
	}
}

func TestFiberGzipBodyInspected(t *testing.T) {
	var zb bytes.Buffer
	zw := gzip.NewWriter(&zb)
	_, _ = zw.Write([]byte(`{"q":"1' OR '1'='1"}`))
	_ = zw.Close()
	var calls atomic.Int32
	app := newApp(Config{Firewall: newFW(t, aegolith.Config{})}, &calls)
	req := httptest.NewRequest("POST", "/x", bytes.NewReader(zb.Bytes()))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	if code, _, _ := do(t, app, req); code != 403 || calls.Load() != 0 {
		t.Fatalf("gzip SQLi must be blocked: code=%d calls=%d", code, calls.Load())
	}
	// A benign gzip body reaches the handler, which sees the decompressed bytes.
	zb.Reset()
	zw = gzip.NewWriter(&zb)
	_, _ = zw.Write([]byte(`{"q":"ok"}`))
	_ = zw.Close()
	req = httptest.NewRequest("POST", "/x", bytes.NewReader(zb.Bytes()))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	code, got, _ := do(t, app, req)
	if code != 200 || string(got) != `{"q":"ok"}` {
		t.Fatalf("code=%d got=%q", code, got)
	}
}

func TestFiberGzipOverLimitPrefixOnly(t *testing.T) {
	var zb bytes.Buffer
	zw := gzip.NewWriter(&zb)
	big := jsonBody(3 << 20)
	_, _ = zw.Write(big)
	_ = zw.Close()
	var saw atomic.Int64
	var oversize atomic.Bool
	// AEG-PROTO-003 is set to monitor explicitly (it blocks by default in
	// core releases after v0.1.0-alpha.1) so the request is flagged and
	// served whichever core version this module resolves.
	app := newApp(Config{
		Firewall: newFW(t, aegolith.Config{RuleActions: map[string]aegolith.Action{"AEG-PROTO-003": aegolith.ActionMonitor}}),
		OnDecision: func(r *aegolith.Request, d aegolith.Decision) {
			saw.Store(int64(len(r.Body)))
			for _, m := range d.Matches {
				if m.RuleID == "AEG-PROTO-003" {
					oversize.Store(true)
				}
			}
		},
	}, nil)
	req := httptest.NewRequest("POST", "/x", bytes.NewReader(zb.Bytes()))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	code, _, _ := do(t, app, req)
	// AEG-PROTO-003 does not block, so up to 2 x limit (+1 byte marking the
	// cut) of the decoded body is inspected.
	if code != 200 || !oversize.Load() || saw.Load() != 2<<20+1 {
		t.Fatalf("code=%d oversize=%v engine body=%d", code, oversize.Load(), saw.Load())
	}
}

func TestFiberHeadBlocks(t *testing.T) {
	var calls atomic.Int32
	app := newApp(Config{Firewall: newFW(t, aegolith.Config{})}, &calls)
	code, _, _ := do(t, app, httptest.NewRequest("HEAD", sqliQuery, nil))
	if code != 403 || calls.Load() != 0 {
		t.Fatalf("code=%d calls=%d", code, calls.Load())
	}
}

func TestFiberMonitorCallsHookAndServes(t *testing.T) {
	var hooked, calls atomic.Int32
	var monitored atomic.Bool
	app := newApp(Config{
		Firewall: newFW(t, aegolith.Config{Mode: aegolith.ModeMonitor}),
		OnDecision: func(_ *aegolith.Request, d aegolith.Decision) {
			hooked.Add(1)
			monitored.Store(d.Monitored)
		},
	}, &calls)
	code, _, _ := do(t, app, httptest.NewRequest("GET", sqliQuery, nil))
	if code != 200 || hooked.Load() != 1 || !monitored.Load() || calls.Load() != 1 {
		t.Fatalf("code=%d hooked=%d monitored=%v calls=%d", code, hooked.Load(), monitored.Load(), calls.Load())
	}
}

func TestFiberRequestFieldsCopied(t *testing.T) {
	var got *aegolith.Request
	app := newApp(Config{
		Firewall:   newFW(t, aegolith.Config{Mode: aegolith.ModeMonitor}),
		OnDecision: func(r *aegolith.Request, _ aegolith.Decision) { got = r },
	}, nil)
	req := httptest.NewRequest("POST", "/a%2Fb?id=1%27%20OR%20%271%27%3D%271", strings.NewReader(`{"a":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("X-Dup", "one")
	req.Header.Add("X-Dup", "two")
	req.Host = "example.test"
	do(t, app, req)
	if got == nil {
		t.Fatal("hook not called")
	}
	if got.Method != "POST" || got.RawPath != "/a%2Fb" || got.RawQuery != "id=1%27%20OR%20%271%27%3D%271" {
		t.Fatalf("method=%q path=%q query=%q", got.Method, got.RawPath, got.RawQuery)
	}
	if v := got.Header.Values("X-Dup"); len(v) != 2 || v[0] != "one" || v[1] != "two" {
		t.Fatalf("duplicate header lost: %v", got.Header)
	}
	if got.Header.Get("Host") != "example.test" || got.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("headers %v", got.Header)
	}
	if got.RemoteAddr == "" {
		t.Fatal("empty RemoteAddr")
	}
	if string(got.Body) != `{"a":1}` {
		t.Fatalf("body %q", got.Body)
	}
}

// The values handed to the hook must stay valid after fasthttp reuses its
// buffers for later requests.
func TestFiberRequestSurvivesBufferReuse(t *testing.T) {
	var mu sync.Mutex
	var kept []*aegolith.Request
	app := newApp(Config{
		Firewall: newFW(t, aegolith.Config{Mode: aegolith.ModeMonitor}),
		OnDecision: func(r *aegolith.Request, _ aegolith.Decision) {
			mu.Lock()
			kept = append(kept, r)
			mu.Unlock()
		},
	}, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = app.Listener(ln) }()
	defer app.Shutdown()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	br := bufio.NewReader(c)
	send := func(path, hdr, body string) {
		req := "POST " + path + " HTTP/1.1\r\nHost: a\r\nContent-Type: application/json\r\nX-H: " + hdr +
			"\r\nContent-Length: " + itoa(len(body)) + "\r\n\r\n" + body
		if _, err := c.Write([]byte(req)); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	send("/first?q=%27%20OR%201%3D1", "AAAAAAAA", `{"q":"1' OR '1'='1"}`)
	send("/zzzzzzzzzzzz?z=%27%20OR%209%3D9", "ZZZZZZZZ", `{"z":"1' OR '9'='9"}`)
	mu.Lock()
	defer mu.Unlock()
	if len(kept) != 2 {
		t.Fatalf("hooks %d", len(kept))
	}
	r := kept[0]
	if r.Method != "POST" || r.RawPath != "/first" || r.RawQuery != "q=%27%20OR%201%3D1" ||
		r.Header.Get("X-H") != "AAAAAAAA" || string(r.Body) != `{"q":"1' OR '1'='1"}` {
		t.Fatalf("first request corrupted by buffer reuse: %+v", r)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

// rawServer runs a real Fiber server with the middleware in monitor mode and
// returns what the engine saw for one raw request. The 30 s deadline only
// guards against a hang; a response normally arrives in milliseconds, and a
// loaded machine must not turn a slow response into a failure.
func rawServer(t *testing.T, raw string) (seen http.Header, status int) {
	t.Helper()
	return rawServerWait(t, raw, 30*time.Second)
}

// rawServerWait is rawServer with an explicit deadline, for a request that
// is expected never to complete (the wait is how long to give it).
func rawServerWait(t *testing.T, raw string, wait time.Duration) (seen http.Header, status int) {
	t.Helper()
	var mu sync.Mutex
	app := newApp(Config{
		Firewall: newFW(t, aegolith.Config{Mode: aegolith.ModeMonitor}),
		OnDecision: func(r *aegolith.Request, _ aegolith.Decision) {
			mu.Lock()
			seen = r.Header
			mu.Unlock()
		},
	}, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = app.Listener(ln) }()
	defer app.Shutdown()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(wait))
	if _, err := c.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Logf("no response: %v", err)
		mu.Lock()
		defer mu.Unlock()
		return seen, 0
	}
	_ = resp.Body.Close()
	mu.Lock()
	defer mu.Unlock()
	return seen, resp.StatusCode
}

// Through a real fasthttp server the raw smuggling variants are normalised by
// fasthttp's own parser before any middleware runs; these assertions record
// what actually reaches the engine so a fasthttp upgrade that changes it is
// noticed:
//   - Transfer-Encoding: chunked + Content-Length: the Content-Length is
//     dropped, the engine sees only Transfer-Encoding.
//   - duplicate Content-Length: collapsed to one header (the last value).
//   - duplicate Transfer-Encoding: collapsed to one header (the first).
//   - an unknown Transfer-Encoding (xchunked): the request never completes
//     and the handler is never reached.
func TestRealServerSmugglingHeadersReachEngine(t *testing.T) {
	const pre = "POST /x HTTP/1.1\r\nHost: a\r\nContent-Type: application/json\r\nConnection: close\r\n"
	seen, status := rawServer(t, pre+"Transfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n3\r\nabc\r\n0\r\n\r\n")
	if status != 200 || seen.Get("Transfer-Encoding") != "chunked" || len(seen.Values("Content-Length")) != 0 {
		t.Fatalf("TE+CL: status=%d seen=%v", status, seen)
	}
	seen, status = rawServer(t, pre+"Content-Length: 5\r\nContent-Length: 6\r\n\r\nabcdef")
	if v := seen.Values("Content-Length"); status != 200 || len(v) != 1 || v[0] != "6" {
		t.Fatalf("dup CL: status=%d seen=%v", status, seen)
	}
	seen, status = rawServer(t, pre+"Transfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n3\r\nabc\r\n0\r\n\r\n")
	if v := seen.Values("Transfer-Encoding"); status != 200 || len(v) != 1 || v[0] != "chunked" {
		t.Fatalf("dup TE: status=%d seen=%v", status, seen)
	}
	// Never completes: one second is enough to show the handler is not
	// reached, and load can only delay the server further.
	seen, status = rawServerWait(t, pre+"Transfer-Encoding: xchunked\r\nContent-Length: 3\r\n\r\nabc", time.Second)
	if seen != nil || status != 0 {
		t.Fatalf("xchunked: status=%d seen=%v (handler reached)", status, seen)
	}
}

// Duplicate headers that fasthttp keeps (e.g. repeated X-Forwarded-For) reach
// the engine in order, none dropped.
func TestRealServerDuplicateHeadersPreserved(t *testing.T) {
	const raw = "GET /x?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1\r\nHost: a\r\nX-Forwarded-For: 1.1.1.1\r\nX-Forwarded-For: 2.2.2.2\r\nConnection: close\r\n\r\n"
	seen, status := rawServer(t, raw)
	if v := seen.Values("X-Forwarded-For"); status != 200 || len(v) != 2 || v[0] != "1.1.1.1" || v[1] != "2.2.2.2" {
		t.Fatalf("status=%d seen=%v", status, seen)
	}
}

func TestFiberNoSyntheticContentLengthZero(t *testing.T) {
	var seen http.Header
	app := newApp(Config{
		Firewall:   newFW(t, aegolith.Config{}),
		OnDecision: func(r *aegolith.Request, _ aegolith.Decision) { seen = r.Header },
	}, nil)
	do(t, app, httptest.NewRequest("GET", sqliQuery, nil))
	if seen == nil {
		t.Fatal("hook not called")
	}
	if _, ok := seen["Content-Length"]; ok {
		t.Fatalf("synthetic Content-Length: %v", seen)
	}
}

func TestFiberRequestIDSanitised(t *testing.T) {
	cases := map[string]bool{
		"abc-123_X.y":           true,
		"a b":                   false,
		`a"b`:                   false,
		strings.Repeat("a", 64): true,
		strings.Repeat("a", 65): false,
		"</script>":             false,
		"\u00e9":                false,
	}
	app := newApp(Config{Firewall: newFW(t, aegolith.Config{})}, nil)
	for in, keep := range cases {
		req := httptest.NewRequest("GET", sqliQuery, nil)
		req.Header["X-Request-Id"] = []string{in}
		code, body, _ := do(t, app, req)
		var m map[string]string
		if err := json.Unmarshal(body, &m); err != nil || code != 403 {
			t.Fatalf("%q: code=%d body=%q err=%v", in, code, body, err)
		}
		if keep && m["request_id"] != in {
			t.Errorf("%q: got %q", in, m["request_id"])
		}
		if !keep && (m["request_id"] == in || len(m["request_id"]) != 16) {
			t.Errorf("%q: expected generated id, got %q", in, m["request_id"])
		}
	}
	// No header at all: generated.
	_, body, _ := do(t, app, httptest.NewRequest("GET", sqliQuery, nil))
	var m map[string]string
	if err := json.Unmarshal(body, &m); err != nil || len(m["request_id"]) != 16 {
		t.Fatalf("body %q", body)
	}
	// Config.RequestID wins and hostile ids still yield valid JSON.
	app = newApp(Config{
		Firewall:  newFW(t, aegolith.Config{}),
		RequestID: func(*fiber.Ctx) string { return "a\"</b>\n" },
	}, nil)
	_, body, _ = do(t, app, httptest.NewRequest("GET", sqliQuery, nil))
	if err := json.Unmarshal(body, &m); err != nil || m["request_id"] != "a\"</b>\n" {
		t.Fatalf("body %q err %v", body, err)
	}
}

func TestFiberHookPanicDoesNotBreakServing(t *testing.T) {
	var calls atomic.Int32
	app := newApp(Config{
		Firewall:   newFW(t, aegolith.Config{Mode: aegolith.ModeMonitor}),
		OnDecision: func(*aegolith.Request, aegolith.Decision) { panic("bad hook") },
	}, &calls)
	if code, _, _ := do(t, app, httptest.NewRequest("GET", sqliQuery, nil)); code != 200 || calls.Load() != 1 {
		t.Fatalf("code=%d calls=%d", code, calls.Load())
	}
	// A panicking hook on a block still blocks.
	calls.Store(0)
	app = newApp(Config{
		Firewall:   newFW(t, aegolith.Config{}),
		OnDecision: func(*aegolith.Request, aegolith.Decision) { panic("bad hook") },
	}, &calls)
	if code, _, _ := do(t, app, httptest.NewRequest("GET", sqliQuery, nil)); code != 403 || calls.Load() != 0 {
		t.Fatalf("code=%d calls=%d", code, calls.Load())
	}
}

func TestFiberNilFirewallPassesThrough(t *testing.T) {
	var calls, hooked atomic.Int32
	app := newApp(Config{
		OnDecision: func(_ *aegolith.Request, d aegolith.Decision) {
			hooked.Add(1)
			if d.Err == nil {
				t.Error("expected Err")
			}
		},
	}, &calls)
	code, _, _ := do(t, app, httptest.NewRequest("GET", sqliQuery, nil))
	if code != 200 || calls.Load() != 1 || hooked.Load() != 1 {
		t.Fatalf("code=%d calls=%d hooked=%d", code, calls.Load(), hooked.Load())
	}
}

func TestFiberMaxInt64LimitNoOverflow(t *testing.T) {
	app := newApp(Config{Firewall: newFW(t, aegolith.Config{Limits: aegolith.Limits{MaxBodyBytes: 1<<63 - 1}})}, nil)
	req := httptest.NewRequest("POST", "/x", strings.NewReader(`{"a":1}`))
	req.Header.Set("Content-Type", "application/json")
	if code, got, _ := do(t, app, req); code != 200 || string(got) != `{"a":1}` {
		t.Fatalf("code=%d got=%q", code, got)
	}
}

// Identical inputs get identical decisions under concurrency, for both an
// enforcing and a monitoring firewall.
func TestFiberConcurrentIdenticalDecisions(t *testing.T) {
	for _, mode := range []aegolith.Mode{aegolith.ModeEnforce, aegolith.ModeMonitor} {
		var mu sync.Mutex
		var rules []string
		app := newApp(Config{
			Firewall: newFW(t, aegolith.Config{Mode: mode}),
			OnDecision: func(r *aegolith.Request, d aegolith.Decision) {
				if r.RawQuery == "" {
					return // only the SQLi requests are compared
				}
				var ids []string
				for _, m := range d.Matches {
					ids = append(ids, m.RuleID)
				}
				mu.Lock()
				rules = append(rules, strconv.Itoa(int(d.Action))+"|"+strings.Join(ids, ","))
				mu.Unlock()
			},
		}, nil)
		want := 200
		if mode == aegolith.ModeEnforce {
			want = 403
		}
		var wg sync.WaitGroup
		for i := 0; i < 32; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				if i%2 == 0 {
					code, _, _ := doErr(app, httptest.NewRequest("GET", sqliQuery, nil))
					if code != want {
						t.Errorf("mode %v: code %d want %d", mode, code, want)
					}
					return
				}
				req := httptest.NewRequest("POST", "/x", bytes.NewReader(jsonBody(50000)))
				req.Header.Set("Content-Type", "application/json")
				if code, _, _ := doErr(app, req); code != 200 {
					t.Errorf("clean request code %d", code)
				}
			}(i)
		}
		wg.Wait()
		mu.Lock()
		if len(rules) != 16 {
			t.Fatalf("mode %v: hook calls %d, want 16", mode, len(rules))
		}
		for _, r := range rules {
			if r != rules[0] {
				t.Fatalf("mode %v: differing decisions %q vs %q", mode, r, rules[0])
			}
		}
		mu.Unlock()
	}
}

// doErr is do without t.Fatal so it is safe off the test goroutine.
func doErr(app *fiber.App, req *http.Request) (int, []byte, http.Header) {
	resp, err := app.Test(req, -1)
	if err != nil {
		return 0, nil, nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, resp.Header
}

// TestFiberCaseVariantPathKeepsRoutePolicy: Fiber routes case-insensitively
// by default, so "/API/v1/cart/items" reaches the "/api/v1/cart/items"
// handler. The route policy (typed fields, unknown_fields block) must apply
// to every variant that reaches the handler.
func TestFiberCaseVariantPathKeepsRoutePolicy(t *testing.T) {
	block := aegolith.ActionBlock
	fw := newFW(t, aegolith.Config{Mode: aegolith.ModeEnforce, Routes: []aegolith.Route{{
		Method: "POST",
		Path:   "/api/v1/cart/items",
		Body: map[string]aegolith.Field{
			"product_id": {Type: aegolith.TypeUUID},
			"qty":        {Type: aegolith.TypeInt},
		},
		UnknownFields: &block,
	}}})
	const bad = `{"product_id":"not-a-uuid","qty":"lots","is_admin":true}`
	const good = `{"product_id":"4b8e2f1a-9c3d-4e5f-8a7b-1c2d3e4f5a6b","qty":2}`
	for _, sensitive := range []bool{false, true} {
		var calls atomic.Int32
		app := fiber.New(fiber.Config{DisableStartupMessage: true, CaseSensitive: sensitive})
		app.Use(New(Config{Firewall: fw}))
		app.Post("/api/v1/cart/items", func(c *fiber.Ctx) error {
			calls.Add(1)
			return c.SendStatus(200)
		})
		for _, c := range []struct {
			path, body string
			want       int
		}{
			{"/api/v1/cart/items", bad, 403},
			{"/API/v1/cart/items", bad, 403},
			{"/Api/V1/Cart/Items", bad, 403},
			{"/api/v1/cart/items/", bad, 403},
			{"/api/v1/cart/items", good, 200},
			{"/API/v1/cart/items", good, 200},
		} {
			if sensitive && c.path != strings.ToLower(c.path) {
				// Fiber itself 404s case variants when CaseSensitive is set.
				c.want = 404
			}
			calls.Store(0)
			req := httptest.NewRequest("POST", c.path, strings.NewReader(c.body))
			req.Header.Set("Content-Type", "application/json")
			code, _, _ := do(t, app, req)
			if code != c.want {
				t.Errorf("CaseSensitive=%v %s %s: status %d, want %d", sensitive, c.path, c.body, code, c.want)
			}
			if reached := calls.Load() > 0; reached != (c.want == 200) {
				t.Errorf("CaseSensitive=%v %s: handler reached=%v", sensitive, c.path, reached)
			}
		}
	}
}

// TestFiberOverLimitPaddingRuleAction: with AEG-PROTO-003 set to block (the
// core default after v0.1.0-alpha.1), an attack pushed past MaxBodyBytes by
// padding is refused. Set to monitor, the engine inspects up to
// 2 x MaxBodyBytes, so an attack within that is still refused by its own
// rule; one pushed past 2 x MaxBodyBytes reaches the handler, which is the
// documented trade-off. Both actions are explicit so the test holds for
// whichever core version this module resolves; the default itself is
// pinned by the core and httpwaf tests.
func TestFiberOverLimitPaddingRuleAction(t *testing.T) {
	monitor003 := aegolith.Config{Mode: aegolith.ModeEnforce, RuleActions: map[string]aegolith.Action{"AEG-PROTO-003": aegolith.ActionMonitor}}
	padded := func(n int) string { return `{"pad":"` + strings.Repeat("a", n) + `","q":"1' OR '1'='1"}` }
	for _, c := range []struct {
		name string
		cfg  aegolith.Config
		body string
		want int
	}{
		{"proto-003 monitor, attack within 2x", monitor003, padded(1 << 20), 403},
		{"proto-003 monitor, attack past 2x", monitor003, padded(2 << 20), 200},
		{"proto-003 block", aegolith.Config{Mode: aegolith.ModeEnforce, RuleActions: map[string]aegolith.Action{"AEG-PROTO-003": aegolith.ActionBlock}}, padded(1 << 20), 403},
	} {
		var calls atomic.Int32
		app := newApp(Config{Firewall: newFW(t, c.cfg)}, &calls)
		req := httptest.NewRequest("POST", "/search", strings.NewReader(c.body))
		req.Header.Set("Content-Type", "application/json")
		code, _, _ := do(t, app, req)
		if code != c.want || (calls.Load() > 0) != (c.want == 200) {
			t.Errorf("%s: code=%d calls=%d, want %d", c.name, code, calls.Load(), c.want)
		}
	}
}

// TestRouteFoldCachedPerApp: the app config is read once per app, not per
// request, and one middleware mounted on two apps answers for each.
func TestRouteFoldCachedPerApp(t *testing.T) {
	var loads atomic.Int32
	f := &routeFold{load: func(app *fiber.App) bool { loads.Add(1); return appFoldsRoutes(app) }}
	folding := fiber.New()
	strict := fiber.New(fiber.Config{CaseSensitive: true})
	for range 100 {
		if !f.get(folding) {
			t.Fatal("default app should fold")
		}
	}
	if loads.Load() != 1 {
		t.Fatalf("config read %d times for one app", loads.Load())
	}
	if f.get(strict) || !f.get(folding) {
		t.Fatal("wrong answer after switching apps")
	}

	// End to end: one handler on both apps. With folding, /API/... matches
	// the route and the non-int id is a schema block; case-sensitive, it is
	// an unknown route (monitor), so the request is served.
	h := New(Config{Firewall: newFW(t, aegolith.Config{
		Mode:   aegolith.ModeEnforce,
		Routes: []aegolith.Route{{Method: "GET", Path: "/api/v1/orders/:id", PathParams: map[string]aegolith.Field{"id": {Type: aegolith.TypeInt}}}},
	})})
	for _, app := range []*fiber.App{folding, strict} {
		app.Use(h)
		app.Get("/*", func(c *fiber.Ctx) error { return c.SendString("ok") })
	}
	for i, c := range []struct {
		app  *fiber.App
		want int
	}{{folding, 403}, {strict, 200}, {folding, 403}, {strict, 200}} {
		code, _, _ := do(t, c.app, httptest.NewRequest("GET", "/API/v1/orders/abc", nil))
		if code != c.want {
			t.Fatalf("step %d: code=%d want %d", i, code, c.want)
		}
	}
}

// overCapBody is a ~1.5 MiB JSON body (over the 1 MiB default cap, within
// the engine's 2 x cap inspection limit) with an attack after the padding.
func overCapBody() []byte {
	return []byte(`{"pad":"` + strings.Repeat("a", 3<<19) + `","q":"1 UNION SELECT password FROM users"}`)
}

// G8: in monitor mode an over-cap body is handed to the engine up to its
// inspection limit (2 x MaxBodyBytes), so an attack after 1 MiB of padding
// is seen, and the complete JSON does not raise AEG-PROTO-020. The handler
// still gets the whole body when the request is served.
func TestFiberMonitorInspectsOverCapBody(t *testing.T) {
	body := overCapBody()
	for _, c := range []struct {
		name string
		cfg  aegolith.Config
		want int
	}{
		{"monitor mode", aegolith.Config{Mode: aegolith.ModeMonitor}, 200},
		// Enforce with only AEG-PROTO-003 monitored: the attack past the
		// cap is now seen, so its own rule blocks.
		{"proto-003 monitor", aegolith.Config{Mode: aegolith.ModeEnforce, RuleActions: map[string]aegolith.Action{"AEG-PROTO-003": aegolith.ActionMonitor}}, 403},
	} {
		cfg := c.cfg
		t.Run(c.name, func(t *testing.T) {
			var saw atomic.Int64
			var rules sync.Map
			app := newApp(Config{
				Firewall: newFW(t, cfg),
				OnDecision: func(r *aegolith.Request, d aegolith.Decision) {
					saw.Store(int64(len(r.Body)))
					for _, m := range d.Matches {
						rules.Store(m.RuleID, true)
					}
				},
			}, nil)
			req := httptest.NewRequest("POST", "/api/v1/search", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			code, got, _ := do(t, app, req)
			has := func(id string) bool { _, ok := rules.Load(id); return ok }
			if code != c.want || (c.want == 200 && !bytes.Equal(got, body)) {
				t.Fatalf("code=%d (want %d) len(got)=%d len(want)=%d", code, c.want, len(got), len(body))
			}
			if saw.Load() != int64(len(body)) || !has("AEG-PROTO-003") || !has("AEG-SQLI-001") || has("AEG-PROTO-020") {
				t.Fatalf("engine body=%d (want %d) proto003=%v sqli=%v proto020=%v",
					saw.Load(), len(body), has("AEG-PROTO-003"), has("AEG-SQLI-001"), has("AEG-PROTO-020"))
			}
		})
	}
}

// In enforce mode (AEG-PROTO-003 blocks) the same request is still refused
// and only MaxBodyBytes+1 bytes are copied; in monitor mode a body longer
// than 2 x MaxBodyBytes is copied only up to 2 x MaxBodyBytes+1 (the extra
// byte tells the engine it was cut).
func TestFiberOverCapCopyBounded(t *testing.T) {
	const limit = 1 << 20
	for _, c := range []struct {
		name     string
		cfg      aegolith.Config
		body     []byte
		wantCode int
		wantCopy int64
	}{
		{"enforce", aegolith.Config{Mode: aegolith.ModeEnforce}, overCapBody(), 403, limit + 1},
		{"enforce 3x", aegolith.Config{Mode: aegolith.ModeEnforce}, jsonBody(3 * limit), 403, limit + 1},
		{"monitor 3x", aegolith.Config{Mode: aegolith.ModeMonitor}, jsonBody(3 * limit), 200, 2*limit + 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			var saw atomic.Int64
			var calls atomic.Int32
			app := newApp(Config{
				Firewall:   newFW(t, c.cfg),
				OnDecision: func(r *aegolith.Request, _ aegolith.Decision) { saw.Store(int64(len(r.Body))) },
			}, &calls)
			req := httptest.NewRequest("POST", "/api/v1/search", bytes.NewReader(c.body))
			req.Header.Set("Content-Type", "application/json")
			code, _, _ := do(t, app, req)
			if code != c.wantCode || (calls.Load() > 0) != (c.wantCode == 200) || saw.Load() != c.wantCopy {
				t.Fatalf("code=%d calls=%d engine body=%d, want code %d and %d bytes", code, calls.Load(), saw.Load(), c.wantCode, c.wantCopy)
			}
		})
	}
}

// bodyCopyLimit: 2 x MaxBodyBytes+1 only when the probe shows AEG-PROTO-003
// does not block; MaxBodyBytes+1 for a nil firewall, an enforcing one, a
// limit too large to probe, and without overflow at MaxInt64.
func TestBodyCopyLimit(t *testing.T) {
	small := aegolith.Limits{MaxBodyBytes: 4096}
	big := aegolith.Limits{MaxBodyBytes: maxProbeBody + 1}
	for _, c := range []struct {
		name string
		fw   *aegolith.Firewall
		want int64
	}{
		{"nil", nil, 1<<20 + 1},
		{"enforce", newFW(t, aegolith.Config{Limits: small}), 4097},
		{"monitor", newFW(t, aegolith.Config{Mode: aegolith.ModeMonitor, Limits: small}), 8193},
		{"proto-003 monitor", newFW(t, aegolith.Config{Limits: small, RuleActions: map[string]aegolith.Action{"AEG-PROTO-003": aegolith.ActionMonitor}}), 8193},
		{"monitor over probe cap", newFW(t, aegolith.Config{Mode: aegolith.ModeMonitor, Limits: big}), maxProbeBody + 2},
		{"maxint64", newFW(t, aegolith.Config{Mode: aegolith.ModeMonitor, Limits: aegolith.Limits{MaxBodyBytes: 1<<63 - 1}}), 1<<63 - 1},
	} {
		if got := bodyCopyLimit(c.fw); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
}
