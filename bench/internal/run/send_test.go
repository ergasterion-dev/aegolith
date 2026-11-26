package run

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
)

const testTimeout = 5 * time.Second

func parseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// serveTest starts a loopback server for the test.
func serveTest(t *testing.T, h http.HandlerFunc) *url.URL {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return parseURL(t, srv.URL)
}

// capture accepts one request on loopback, answers 200 and gives the request
// byte for byte as it arrived. It reads the framing net/http itself writes.
func capture(t *testing.T) (*url.URL, <-chan string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan string, 1)
	done := make(chan struct{})
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
	})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(testTimeout)); err != nil {
			return
		}
		var raw strings.Builder
		br := bufio.NewReader(conn)
		length, chunked := 0, false
		for {
			line, err := br.ReadString('\n')
			raw.WriteString(line)
			if err != nil || line == "\r\n" {
				break
			}
			if v, ok := strings.CutPrefix(line, "Content-Length: "); ok {
				length, _ = strconv.Atoi(strings.TrimSpace(v))
			}
			chunked = chunked || line == "Transfer-Encoding: chunked\r\n"
		}
		if chunked {
			for !strings.HasSuffix(raw.String(), "\r\n0\r\n\r\n") {
				line, err := br.ReadString('\n')
				raw.WriteString(line)
				if err != nil {
					break
				}
			}
		} else if _, err := io.CopyN(&raw, br, int64(length)); err != nil {
			return
		}
		got <- raw.String()
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	}()
	return &url.URL{Scheme: "http", Host: listener.Addr().String()}, got
}

func TestSendKeepsRawPath(t *testing.T) {
	t.Parallel()
	type seen struct{ path, query string }
	got := make(chan seen, 1)
	base := serveTest(t, func(_ http.ResponseWriter, r *http.Request) {
		got <- seen{r.URL.EscapedPath(), r.URL.RawQuery}
	})
	client := NewClient(testTimeout)
	tests := []struct{ path, query string }{
		{path: "/a/%2e%2e/b"},
		{path: "/a/../b/./c//d"},
		{path: "/a%2Fb%252e", query: "q=%27+OR&q=a;b&%zz&x"},
		{path: "//a/%2e%2e//b", query: "n=1"},
		{path: "/%C0%AF/;jsessionid=1", query: "?"},
	}
	for _, tt := range tests {
		status, latency, err := Send(context.Background(), client, base,
			cases.Case{Method: "GET", Path: tt.path, RawQuery: tt.query}, "r1")
		if err != nil || status != http.StatusOK || latency <= 0 {
			t.Fatalf("%s: status %d, latency %v, err %v", tt.path, status, latency, err)
		}
		if g := <-got; g.path != tt.path || g.query != tt.query {
			t.Errorf("arrived as %q ? %q, want %q ? %q", g.path, g.query, tt.path, tt.query)
		}
	}
}

// The expected bytes are the whole request: nothing may be added, such as a
// User-Agent or Accept-Encoding of the client, and nothing lost.
func TestSendWritesTheCaseAsGiven(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		c    cases.Case
		want string // HOST stands for the server's address
	}{
		"nothing added": {
			c:    cases.Case{Method: "GET", Path: "/x", RawQuery: "a=<b>\"|{}\\^`"},
			want: "GET /x?a=<b>\"|{}\\^` HTTP/1.1\r\nHost: HOST\r\nX-Request-Id: r1\r\n\r\n",
		},
		"path net/url would re-encode": {
			c:    cases.Case{Method: "GET", Path: "/<a>/\"b\"/{c}|\\^`"},
			want: "GET /<a>/\"b\"/{c}|\\^` HTTP/1.1\r\nHost: HOST\r\nX-Request-Id: r1\r\n\r\n",
		},
		"two leading slashes": {
			c:    cases.Case{Method: "GET", Path: "//evil.test/x", RawQuery: "q=1"},
			want: "GET //evil.test/x?q=1 HTTP/1.1\r\nHost: HOST\r\nX-Request-Id: r1\r\n\r\n",
		},
		"two leading slashes that need the absolute form": {
			c:    cases.Case{Method: "GET", Path: "//evil.test/<x>"},
			want: "GET http://HOST//evil.test/<x> HTTP/1.1\r\nHost: HOST\r\nX-Request-Id: r1\r\n\r\n",
		},
		"headers and body": {
			c: cases.Case{Method: "POST", Path: "/x", Body: []byte("a\x00b"), Headers: map[string]string{
				"User-Agent": "probe/1", "Cookie": "a=1; b=<x>", "content-type": "text/plain", "Accept-Encoding": "br",
			}},
			want: "POST /x HTTP/1.1\r\nHost: HOST\r\nUser-Agent: probe/1\r\nContent-Length: 3\r\nAccept-Encoding: br\r\n" +
				"Content-Type: text/plain\r\nCookie: a=1; b=<x>\r\nX-Request-Id: r1\r\n\r\na\x00b",
		},
		"empty user agent": {
			c:    cases.Case{Method: "GET", Path: "/x", Headers: map[string]string{"User-Agent": ""}},
			want: "GET /x HTTP/1.1\r\nHost: HOST\r\nX-Request-Id: r1\r\nuser-agent: \r\n\r\n",
		},
		"host as given": {
			c:    cases.Case{Method: "GET", Path: "/x", Headers: map[string]string{"host": "shop.example.test:8443"}},
			want: "GET /x HTTP/1.1\r\nHost: shop.example.test:8443\r\nX-Request-Id: r1\r\n\r\n",
		},
		"matching content length": {
			c:    cases.Case{Method: "PUT", Path: "/x", Body: []byte("ab"), Headers: map[string]string{"Content-Length": "2"}},
			want: "PUT /x HTTP/1.1\r\nHost: HOST\r\nContent-Length: 2\r\nX-Request-Id: r1\r\n\r\nab",
		},
		"zero content length on an empty post": {
			c:    cases.Case{Method: "POST", Path: "/x", Headers: map[string]string{"Content-Length": "0"}},
			want: "POST /x HTTP/1.1\r\nHost: HOST\r\nContent-Length: 0\r\nX-Request-Id: r1\r\n\r\n",
		},
		"chunked": {
			c:    cases.Case{Method: "POST", Path: "/x", Body: []byte("abc"), Headers: map[string]string{"Transfer-Encoding": "chunked"}},
			want: "POST /x HTTP/1.1\r\nHost: HOST\r\nTransfer-Encoding: chunked\r\nX-Request-Id: r1\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
		},
		"chunked without a body": {
			c:    cases.Case{Method: "GET", Path: "/x", Headers: map[string]string{"Transfer-Encoding": "chunked"}},
			want: "GET /x HTTP/1.1\r\nHost: HOST\r\nTransfer-Encoding: chunked\r\nX-Request-Id: r1\r\n\r\n0\r\n\r\n",
		},
		"unusual transfer encoding without a body": {
			c:    cases.Case{Method: "GET", Path: "/x", Headers: map[string]string{"Transfer-Encoding": "chunked, identity"}},
			want: "GET /x HTTP/1.1\r\nHost: HOST\r\nConnection: close\r\nX-Request-Id: r1\r\ntransfer-encoding: chunked, identity\r\n\r\n",
		},
		"trailer header": {
			c:    cases.Case{Method: "GET", Path: "/x", Headers: map[string]string{"Trailer": "X-Sum"}},
			want: "GET /x HTTP/1.1\r\nHost: HOST\r\nX-Request-Id: r1\r\ntrailer: X-Sum\r\n\r\n",
		},
		"connect keeps the path": {
			c:    cases.Case{Method: "CONNECT", Path: "/x"},
			want: "CONNECT /x HTTP/1.1\r\nHost: HOST\r\nX-Request-Id: r1\r\n\r\n",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			base, got := capture(t)
			status, _, err := Send(context.Background(), NewClient(testTimeout), base, tt.c, "r1")
			if err != nil || status != http.StatusOK {
				t.Fatalf("status %d, err %v", status, err)
			}
			select {
			case raw := <-got:
				if want := strings.ReplaceAll(tt.want, "HOST", base.Host); raw != want {
					t.Errorf("sent %q\nwant %q", raw, want)
				}
			case <-time.After(testTimeout):
				t.Fatal("no request arrived")
			}
		})
	}
}

func TestSendDoesNotFollowRedirect(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	other := serveTest(t, func(http.ResponseWriter, *http.Request) { hits.Add(1) })
	for _, code := range []int{http.StatusFound, http.StatusTemporaryRedirect} {
		base := serveTest(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, other.String()+"/elsewhere", code)
		})
		status, _, err := Send(context.Background(), NewClient(testTimeout), base,
			cases.Case{Method: "POST", Path: "/x", Body: []byte("b")}, "r1")
		if err != nil || status != code {
			t.Errorf("status %d, err %v; want %d", status, err, code)
		}
	}
	if got := hits.Load(); got != 0 {
		t.Errorf("the second server was hit %d times", got)
	}
}

func TestIllegalHeaderIsNotSent(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	base := serveTest(t, func(http.ResponseWriter, *http.Request) { hits.Add(1) })
	c := cases.Case{ID: "c1", Method: "GET", Path: "/x", Headers: map[string]string{"X-Note": "secret\nInjected: 1"}}

	status, latency, err := Send(context.Background(), NewClient(testTimeout), base, c, "r1")
	outcome, reason := Classify(status, err, nil, nil)
	if outcome != NotSent || reason == "" {
		t.Errorf("outcome %q, reason %q, err %v; want not-sent with a reason", outcome, reason, err)
	}
	if status != 0 || latency != 0 {
		t.Errorf("status %d, latency %v; want zero", status, latency)
	}
	if strings.Contains(reason+err.Error(), "secret") {
		t.Errorf("reason or error repeats the value: %q, %v", reason, err)
	}

	rs := Detect(context.Background(), NewClient(testTimeout), base, []cases.Case{c}, "p-", 0)
	if len(rs) != 1 || rs[0].Outcome != NotSent || rs[0].Reason == "" {
		t.Errorf("results = %+v, want one not-sent with a reason", rs)
	}
	if got := hits.Load(); got != 0 {
		t.Errorf("the server was hit %d times", got)
	}
}

func TestSendRefusesWhatItWouldAlter(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	base := serveTest(t, func(http.ResponseWriter, *http.Request) { hits.Add(1) })
	get := func(headers map[string]string) cases.Case {
		return cases.Case{Method: "GET", Path: "/x", Headers: headers}
	}
	header := func(name, value string) cases.Case { return get(map[string]string{name: value}) }
	post := func(body string, headers map[string]string) cases.Case {
		return cases.Case{Method: "POST", Path: "/x", Body: []byte(body), Headers: headers}
	}
	tests := map[string]cases.Case{
		"no method":                           {Path: "/x"},
		"method with a space":                 {Method: "GE T", Path: "/x"},
		"relative path":                       {Method: "GET", Path: "x"},
		"control byte in the path":            {Method: "GET", Path: "/x\r\nY: 1"},
		"control byte in the query":           {Method: "GET", Path: "/x", RawQuery: "a=\x00"},
		"header name with a space":            header("X Note", "v"),
		"empty header name":                   header("", "v"),
		"control byte in a value":             header("X-Note", "a\x7f"),
		"names that differ by case":           get(map[string]string{"X-Note": "1", "x-note": "2"}),
		"request id header":                   header("x-request-id", "mine"),
		"empty host":                          header("Host", ""),
		"host net/http would blank":           header("Host", "a.example.test/<x>"),
		"host with a space":                   header("Host", "a b"),
		"host net/http would encode":          header("Host", "bücher.example.test"),
		"host with a zone":                    header("Host", "[fe80::1%en0]:80"),
		"host with an absolute form":          {Method: "GET", Path: "//a/<b>", Headers: map[string]string{"Host": "a.example.test"}},
		"wrong content length":                post("ab", map[string]string{"Content-Length": "3"}),
		"padded content length":               post("ab", map[string]string{"Content-Length": "02"}),
		"content length net/http omits":       header("Content-Length", "0"),
		"chunked and content length":          post("ab", map[string]string{"Content-Length": "2", "Transfer-Encoding": "chunked"}),
		"capitalised chunked":                 header("Transfer-Encoding", "Chunked"),
		"unusual encoding with a body":        post("ab", map[string]string{"Transfer-Encoding": "gzip"}),
		"unusual encoding on a post":          post("", map[string]string{"Transfer-Encoding": "gzip"}),
		"unusual encoding and content length": get(map[string]string{"Transfer-Encoding": "gzip", "Content-Length": "0"}),
	}
	t.Run("cases", func(t *testing.T) {
		for name, c := range tests {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				status, _, err := Send(context.Background(), NewClient(testTimeout), base, c, "r1")
				var refused *NotSentError
				if status != 0 || !errors.As(err, &refused) || refused.Reason == "" {
					t.Errorf("status %d, err %v; want a refusal with a reason", status, err)
				}
			})
		}
		for name, id := range map[string]string{
			"empty request id":  "",
			"long request id":   strings.Repeat("a", 129),
			"id with a space":   "a b",
			"id with a newline": "a\n",
		} {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				_, _, err := Send(context.Background(), NewClient(testTimeout), base, get(nil), id)
				var refused *NotSentError
				if !errors.As(err, &refused) {
					t.Errorf("err %v; want a refusal", err)
				}
			})
		}
		for _, raw := range []string{"ftp://127.0.0.1:1", "http://", "/relative"} {
			t.Run("base "+raw, func(t *testing.T) {
				t.Parallel()
				_, _, err := Send(context.Background(), NewClient(testTimeout), parseURL(t, raw), get(nil), "r1")
				var refused *NotSentError
				if !errors.As(err, &refused) {
					t.Errorf("err %v; want a refusal", err)
				}
			})
		}
	})
	if got := hits.Load(); got != 0 {
		t.Errorf("the server was hit %d times", got)
	}
}

func TestSendErrorDoesNotRepeatTheRequest(t *testing.T) {
	t.Parallel()
	base := serveTest(t, func(w http.ResponseWriter, _ *http.Request) {
		panic(http.ErrAbortHandler) // closes the connection without an answer
	})
	status, _, err := Send(context.Background(), NewClient(testTimeout), base,
		cases.Case{Method: "GET", Path: "/secret-path", RawQuery: "q=secret-query"}, "r1")
	if status != 0 || err == nil {
		t.Fatalf("status %d, err %v; want a transport error", status, err)
	}
	var refused *NotSentError
	if errors.As(err, &refused) {
		t.Errorf("a transport error is not a refusal: %v", err)
	}
	_, reason := Classify(status, err, nil, nil)
	if got := err.Error() + " " + reason; strings.Contains(got, "secret") {
		t.Errorf("the request is repeated: %q", got)
	}
	if !strings.Contains(reason, "connection closed") {
		t.Errorf("reason = %q", reason)
	}
}

func TestSendTimesOut(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	base := serveTest(t, func(http.ResponseWriter, *http.Request) { <-release })
	// Cleanups run last first: the handler is released before the server closes.
	t.Cleanup(func() { close(release) })
	status, _, err := Send(context.Background(), NewClient(50*time.Millisecond), base,
		cases.Case{Method: "GET", Path: "/x"}, "r1")
	if outcome, reason := Classify(status, err, nil, nil); outcome != Unknown || !strings.Contains(reason, "timed out") {
		t.Errorf("outcome %q, reason %q, err %v", outcome, reason, err)
	}
}

func TestNewClientUsesNoProxyOrCookies(t *testing.T) {
	t.Parallel()
	c := NewClient(3 * time.Second)
	transport, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T", c.Transport)
	}
	if transport.Proxy != nil || c.Jar != nil || c.Timeout != 3*time.Second {
		t.Errorf("proxy set %t, jar %v, timeout %v", transport.Proxy != nil, c.Jar, c.Timeout)
	}
	if !transport.DisableCompression {
		t.Error("the client would add Accept-Encoding")
	}
	if p := transport.Protocols; p == nil || !p.HTTP1() || p.HTTP2() || p.UnencryptedHTTP2() {
		t.Errorf("protocols = %v, want HTTP/1 only", p)
	}
}
