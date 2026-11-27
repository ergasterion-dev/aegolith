package remote

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
	"github.com/ergasterion-dev/aegolith/bench/internal/run"
)

// fakeClock starts at a fixed time and moves only when slept on.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{now: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
	return ctx.Err()
}

// hit is one request the test server received.
type hit struct {
	kind    string // "health", "control" or "case"
	method  string
	uri     string
	id      string
	headers http.Header
	body    string
}

// remoteServer is a loopback target that records every request and answers
// with answer, by kind.
type remoteServer struct {
	t      *testing.T
	mu     sync.Mutex
	hits   []hit
	answer func(h hit, n int) int // n counts the hits of that kind, from 1
	after  func(h hit, n int)     // runs after a hit is recorded
	// location is where a redirect points.
	location string
	url      *url.URL
}

func startRemote(t *testing.T, answer func(h hit, n int) int) *remoteServer {
	t.Helper()
	s := &remoteServer{t: t, answer: answer}
	srv := httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	s.url = u
	return s
}

func (s *remoteServer) serve(w http.ResponseWriter, r *http.Request) {
	body := new(strings.Builder)
	_, _ = fmt.Fprint(body, readAll(r))
	h := hit{method: r.Method, uri: r.RequestURI, id: r.Header.Get("X-Request-Id"), headers: r.Header.Clone(), body: body.String()}
	switch {
	case strings.Contains(h.id, "-health-"):
		h.kind = "health"
	case strings.Contains(h.id, "-control-"):
		h.kind = "control"
	default:
		h.kind = "case"
	}
	s.mu.Lock()
	s.hits = append(s.hits, h)
	n := 0
	for _, other := range s.hits {
		if other.kind == h.kind {
			n++
		}
	}
	s.mu.Unlock()
	status := http.StatusOK
	if s.answer != nil {
		status = s.answer(h, n)
	}
	if status == 0 { // drop the connection without an answer
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
		return
	}
	if status >= 300 && status < 400 {
		w.Header().Set("Location", s.location)
	}
	w.WriteHeader(status)
	if s.after != nil {
		s.after(h, n)
	}
}

func readAll(r *http.Request) string {
	b := new(strings.Builder)
	buf := make([]byte, 4096)
	for {
		n, err := r.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			return b.String()
		}
	}
}

func (s *remoteServer) count(kind string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, h := range s.hits {
		if kind == "" || h.kind == kind {
			n++
		}
	}
	return n
}

func (s *remoteServer) all() []hit {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.hits)
}

// remoteTarget is a target for the server: two entries, a query and a JSON
// one.
func remoteTarget(s *remoteServer) Target {
	return Target{
		BaseURL:         "http://" + s.url.Host,
		RequestIDPrefix: "test-",
		Mode:            ModeEnforce,
		HealthPath:      "/health",
		MaxRPS:          10,
		StopStatuses:    []int{429},
		Headers:         map[string]string{"Authorization": "Bearer t"},
		Allow: []Entry{
			{Method: "GET", Path: "/search", Placements: []string{"query:q"}, BenignStatus: []int{200}},
			{Method: "POST", Path: "/notes", Placements: []string{"json:note", "header:X-Note"}, BenignStatus: []int{200}},
		},
	}
}

// planFor places n query attack cases for the target.
func planFor(t *testing.T, target Target, kind string, n int) []cases.Case {
	t.Helper()
	var originals []cases.Case
	for i := range n {
		originals = append(originals, origin(t, fmt.Sprintf("c-%d", i), kind, cases.Attack, fmt.Sprintf("1 OR %d=%d", i, i)))
	}
	plan, err := Prepare(originals, nil, target)
	if err != nil {
		t.Fatal(err)
	}
	return plan.Send
}

func options(s *remoteServer, target Target, cs []cases.Case) Options {
	return Options{
		Target: target, ConfirmHost: s.url.Host, RPS: 10, Cases: cs, Limit: 1000,
		Clock: newFakeClock(), Client: NewClient(5 * time.Second),
	}
}

func notSent(rs []run.Result) int {
	n := 0
	for _, r := range rs {
		if r.Outcome == run.NotSent {
			n++
		}
	}
	return n
}

func TestRunSendsPlacedCasesAndControls(t *testing.T) {
	t.Parallel()
	s := startRemote(t, nil)
	target := remoteTarget(s)
	cs := append(planFor(t, target, "query", 3), planFor(t, target, "json", 2)...)
	slices.SortFunc(cs, func(a, b cases.Case) int { return strings.Compare(a.ID, b.ID) })
	o := options(s, target, cs)
	o.RunTag = "0123abcd"
	rs, stop, err := Run(context.Background(), o)
	if err != nil || stop != "" {
		t.Fatalf("Run: %v, stop %q", err, stop)
	}
	if len(rs) != 5 || notSent(rs) != 0 {
		t.Fatalf("%d results, %d not sent", len(rs), notSent(rs))
	}
	for i, r := range rs {
		if r.CaseID != cs[i].ID || r.RequestID != "test-0123abcd-"+cs[i].ID || r.Status != 200 || r.Outcome != run.Unknown || r.Reason != ReasonNotJoined {
			t.Errorf("result %d: %+v", i, r)
		}
	}
	hits := s.all()
	if hits[0].kind != "health" {
		t.Errorf("first request is a %s", hits[0].kind)
	}
	// Each entry is proven before the first case and closed after the last.
	var kinds []string
	for _, h := range hits {
		kinds = append(kinds, h.kind)
	}
	first := slices.Index(kinds, "case")
	if first < 0 || strings.Count(strings.Join(kinds[:first], " "), "control") != 2 {
		t.Errorf("request order %v", kinds)
	}
	if s.count("control") != 4 || s.count("case") != 5 {
		t.Errorf("%d controls and %d cases sent", s.count("control"), s.count("case"))
	}
	allowed := map[string]bool{"Authorization": true, "X-Request-Id": true, "Content-Type": true,
		"Content-Length": true, "X-Note": true, "Connection": true}
	for _, h := range hits {
		if !strings.HasPrefix(h.id, "test-0123abcd-") || !run.ValidRequestID(h.id) {
			t.Errorf("request ID %q", h.id)
		}
		path, _, _ := strings.Cut(h.uri, "?")
		if !slices.Contains([]string{"/health", "/search", "/notes"}, path) {
			t.Errorf("request to %s", h.uri)
		}
		for name := range h.headers {
			if !allowed[name] {
				t.Errorf("%s request sent header %s", h.kind, name)
			}
		}
		if h.headers.Get("Authorization") != "Bearer t" {
			t.Errorf("%s request lacks the target file's header", h.kind)
		}
		if strings.Contains(h.uri, "orig") || strings.Contains(h.body, "orig") || h.headers.Get("Cookie") != "" {
			t.Errorf("%s request carries a part of the original case", h.kind)
		}
		if h.kind == "control" && h.method == "POST" && (h.body != `{"note":"aegobench-control"}` || h.headers.Get("X-Note") != "aegobench-control") {
			t.Errorf("control body %q, header %q", h.body, h.headers.Get("X-Note"))
		}
	}
}

func TestRunTagDiffersBetweenRuns(t *testing.T) {
	t.Parallel()
	s := startRemote(t, nil)
	target := remoteTarget(s)
	cs := planFor(t, target, "query", 1)
	a, _, err := Run(context.Background(), options(s, target, cs))
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := Run(context.Background(), options(s, target, cs))
	if err != nil {
		t.Fatal(err)
	}
	if a[0].RequestID == b[0].RequestID || !strings.HasSuffix(a[0].RequestID, "-"+cs[0].ID) || !run.ValidRequestID(a[0].RequestID) {
		t.Errorf("request IDs %q and %q", a[0].RequestID, b[0].RequestID)
	}
}

func TestStopsOn5xx(t *testing.T) {
	t.Parallel()
	s := startRemote(t, func(h hit, n int) int {
		if h.kind == "case" {
			return http.StatusServiceUnavailable
		}
		return http.StatusOK
	})
	target := remoteTarget(s)
	rs, stop, err := Run(context.Background(), options(s, target, planFor(t, target, "query", 10)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stop, "503") {
		t.Errorf("stop reason %q", stop)
	}
	before := s.count("")
	if s.count("case") != 1 || notSent(rs) != 9 {
		t.Errorf("%d cases sent after a 503, %d not sent", s.count("case"), notSent(rs))
	}
	if s.all()[len(s.all())-1].kind != "case" {
		t.Error("a request followed the 503")
	}
	if s.count("") != before {
		t.Error("requests went on after Run returned")
	}
	for _, r := range rs[1:] {
		if !strings.Contains(r.Reason, "stopped") {
			t.Errorf("unsent reason %q", r.Reason)
		}
	}
}

func TestStopsOnStopStatus(t *testing.T) {
	t.Parallel()
	s := startRemote(t, func(h hit, n int) int {
		if h.kind == "case" && n == 2 {
			return http.StatusTooManyRequests
		}
		return http.StatusOK
	})
	target := remoteTarget(s)
	_, stop, err := Run(context.Background(), options(s, target, planFor(t, target, "query", 10)))
	if err != nil || !strings.Contains(stop, "429") || s.count("case") != 2 {
		t.Errorf("err %v, stop %q, %d cases sent", err, stop, s.count("case"))
	}
}

func TestEnforce403OnAttackIsNotAStop(t *testing.T) {
	t.Parallel()
	s := startRemote(t, func(h hit, n int) int {
		if h.kind == "case" {
			return http.StatusForbidden
		}
		return http.StatusOK
	})
	target := remoteTarget(s)
	rs, stop, err := Run(context.Background(), options(s, target, planFor(t, target, "query", 10)))
	if err != nil || stop != "" || s.count("case") != 10 || notSent(rs) != 0 {
		t.Errorf("err %v, stop %q, %d cases sent", err, stop, s.count("case"))
	}
	for _, r := range rs {
		if r.Status != http.StatusForbidden {
			t.Errorf("status %d", r.Status)
		}
	}
}

func TestBenign403Stops(t *testing.T) {
	t.Parallel()
	s := startRemote(t, func(h hit, n int) int {
		if h.kind == "control" {
			return http.StatusForbidden
		}
		return http.StatusOK
	})
	target := remoteTarget(s)
	rs, stop, err := Run(context.Background(), options(s, target, planFor(t, target, "query", 5)))
	if err != nil || !strings.Contains(stop, "403") {
		t.Errorf("err %v, stop %q", err, stop)
	}
	if s.count("case") != 0 || s.count("control") != 1 || notSent(rs) != 5 {
		t.Errorf("%d cases and %d controls sent", s.count("case"), s.count("control"))
	}
}

func TestFailedControlSendsNoAttack(t *testing.T) {
	t.Parallel()
	// The second entry's control fails; the first entry's cases are not sent
	// either.
	s := startRemote(t, func(h hit, n int) int {
		if h.kind == "control" && h.method == "POST" {
			return http.StatusNotFound
		}
		return http.StatusOK
	})
	target := remoteTarget(s)
	rs, stop, err := Run(context.Background(), options(s, target, planFor(t, target, "query", 5)))
	if err != nil || !strings.Contains(stop, "404") {
		t.Errorf("err %v, stop %q", err, stop)
	}
	if s.count("case") != 0 || notSent(rs) != 5 {
		t.Errorf("%d cases sent after a failed control", s.count("case"))
	}
}

func TestControlRepeatsEvery50Cases(t *testing.T) {
	t.Parallel()
	s := startRemote(t, nil)
	target := remoteTarget(s)
	target.Allow = target.Allow[:1]
	_, stop, err := Run(context.Background(), options(s, target, planFor(t, target, "query", 120)))
	if err != nil || stop != "" {
		t.Fatal(err, stop)
	}
	// Before the first, after the 50th and 100th, and after the last.
	if s.count("control") != 4 {
		t.Errorf("%d controls", s.count("control"))
	}
	var kinds []string
	for _, h := range s.all() {
		if h.kind != "health" {
			kinds = append(kinds, h.kind)
		}
	}
	for _, at := range []int{0, 51, 102, 123} {
		if kinds[at] != "control" {
			t.Errorf("request %d is a %s", at, kinds[at])
		}
	}
}

func TestHealthCheckedEvery5Seconds(t *testing.T) {
	t.Parallel()
	s := startRemote(t, nil)
	target := remoteTarget(s)
	target.Allow = target.Allow[:1]
	o := options(s, target, planFor(t, target, "query", 20))
	o.RPS = 2 // a request every 500 ms of the fake clock
	_, stop, err := Run(context.Background(), o)
	if err != nil || stop != "" {
		t.Fatal(err, stop)
	}
	// 20 cases and 2 controls take about 11 s, with a health check before the
	// first request and one at least every 5 s: 3 or 4 checks with their own
	// slots.
	if n := s.count("health"); n < 3 || n > 4 {
		t.Errorf("%d health checks", n)
	}
	if s.all()[0].kind != "health" {
		t.Error("the first request is not a health check")
	}
}

func TestFailedHealthStops(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusInternalServerError, http.StatusNoContent, http.StatusFound} {
		s := startRemote(t, func(h hit, n int) int {
			if h.kind == "health" {
				return status
			}
			return http.StatusOK
		})
		target := remoteTarget(s)
		_, stop, err := Run(context.Background(), options(s, target, planFor(t, target, "query", 3)))
		if err != nil || !strings.Contains(stop, "health") || s.count("") != 1 {
			t.Errorf("health %d: err %v, stop %q, %d requests", status, err, stop, s.count(""))
		}
	}
	// A health check that fails later stops the run as well.
	s := startRemote(t, func(h hit, n int) int {
		if h.kind == "health" && n == 2 {
			return http.StatusServiceUnavailable
		}
		return http.StatusOK
	})
	target := remoteTarget(s)
	o := options(s, target, planFor(t, target, "query", 40))
	o.RPS = 1
	rs, stop, err := Run(context.Background(), o)
	if err != nil || !strings.Contains(stop, "health") || notSent(rs) == 0 {
		t.Errorf("later health: err %v, stop %q, %d not sent", err, stop, notSent(rs))
	}
	if last := s.all()[len(s.all())-1]; last.kind != "health" {
		t.Errorf("a %s request followed the failed health check", last.kind)
	}
}

func TestStaleHeartbeatStops(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	heartbeat := filepath.Join(dir, "heartbeat")
	if err := os.WriteFile(heartbeat, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	clock := newFakeClock()
	// Already stale: nothing is sent.
	if err := os.Chtimes(heartbeat, clock.Now(), clock.Now().Add(-31*time.Second)); err != nil {
		t.Fatal(err)
	}
	s := startRemote(t, nil)
	target := remoteTarget(s)
	o := options(s, target, planFor(t, target, "query", 5))
	o.Clock, o.HeartbeatFile = clock, heartbeat
	rs, stop, err := Run(context.Background(), o)
	if err != nil || !strings.Contains(stop, "heartbeat") || s.count("") != 0 || notSent(rs) != 5 {
		t.Errorf("stale: err %v, stop %q, %d requests", err, stop, s.count(""))
	}

	// Fresh at the start, stale once 30 s of the clock have passed.
	if err := os.Chtimes(heartbeat, clock.Now(), clock.Now()); err != nil {
		t.Fatal(err)
	}
	o.Cases = planFor(t, target, "query", 60)
	o.RPS = 1
	rs, stop, err = Run(context.Background(), o)
	if err != nil || !strings.Contains(stop, "heartbeat") || notSent(rs) == 0 {
		t.Errorf("going stale: err %v, stop %q, %d not sent", err, stop, notSent(rs))
	}
	if n := s.count(""); n < 25 || n > 31 {
		t.Errorf("%d requests in 30 s at 1 per second", n)
	}

	// Missing.
	o.HeartbeatFile = filepath.Join(dir, "missing")
	before := s.count("")
	_, stop, err = Run(context.Background(), o)
	if err != nil || !strings.Contains(stop, "heartbeat") || s.count("") != before {
		t.Errorf("missing: err %v, stop %q", err, stop)
	}
}

func TestStopFileStops(t *testing.T) {
	t.Parallel()
	stopFile := filepath.Join(t.TempDir(), "stop")
	s := startRemote(t, nil)
	s.after = func(h hit, n int) {
		if h.kind == "case" && n == 3 {
			if err := os.WriteFile(stopFile, nil, 0o600); err != nil {
				t.Error(err)
			}
		}
	}
	target := remoteTarget(s)
	o := options(s, target, planFor(t, target, "query", 10))
	o.StopFile = stopFile
	rs, stop, err := Run(context.Background(), o)
	if err != nil || !strings.Contains(stop, "stop file") {
		t.Errorf("err %v, stop %q", err, stop)
	}
	if s.count("case") != 3 || notSent(rs) != 7 || s.all()[len(s.all())-1].kind != "case" {
		t.Errorf("%d cases sent, %d not sent", s.count("case"), notSent(rs))
	}
	// A stop file present at the start stops everything.
	before := s.count("")
	_, stop, _ = Run(context.Background(), o)
	if !strings.Contains(stop, "stop file") || s.count("") != before {
		t.Errorf("present stop file: stop %q, %d requests", stop, s.count("")-before)
	}
}

func TestCancelStops(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := startRemote(t, nil)
	s.after = func(h hit, n int) {
		if h.kind == "case" && n == 2 {
			cancel()
		}
	}
	target := remoteTarget(s)
	rs, stop, err := Run(ctx, options(s, target, planFor(t, target, "query", 10)))
	if err != nil || !strings.Contains(stop, "interrupted") {
		t.Errorf("err %v, stop %q", err, stop)
	}
	if s.count("case") > 3 || notSent(rs) < 7 {
		t.Errorf("%d cases sent after the cancel", s.count("case"))
	}
}

func TestConsecutiveRedirectsOrErrorsStop(t *testing.T) {
	t.Parallel()
	for name, status := range map[string]int{"redirect": http.StatusFound, "transport error": 0} {
		elsewhere := startRemote(t, nil)
		s := startRemote(t, func(h hit, n int) int {
			if h.kind == "case" {
				return status
			}
			return http.StatusOK
		})
		s.location = elsewhere.url.String() + "/x"
		target := remoteTarget(s)
		rs, stop, err := Run(context.Background(), options(s, target, planFor(t, target, "query", 10)))
		if err != nil || !strings.Contains(stop, "3 requests in a row") {
			t.Errorf("%s: err %v, stop %q", name, err, stop)
		}
		if s.count("case") != 3 || notSent(rs) != 7 {
			t.Errorf("%s: %d cases sent", name, s.count("case"))
		}
		if elsewhere.count("") != 0 {
			t.Errorf("%s: a redirect was followed", name)
		}
	}
	// Two in a row and then an answer is no stop.
	s := startRemote(t, func(h hit, n int) int {
		if h.kind == "case" && n%3 != 0 {
			return http.StatusFound
		}
		return http.StatusOK
	})
	target := remoteTarget(s)
	_, stop, err := Run(context.Background(), options(s, target, planFor(t, target, "query", 9)))
	if err != nil || stop != "" {
		t.Errorf("interleaved redirects: err %v, stop %q", err, stop)
	}
}

func TestLimit(t *testing.T) {
	t.Parallel()
	s := startRemote(t, nil)
	target := remoteTarget(s)
	cs := planFor(t, target, "query", 10)
	o := options(s, target, cs)
	o.Limit = 3
	rs, stop, err := Run(context.Background(), o)
	if err != nil || stop != "" {
		t.Fatal(err, stop)
	}
	if s.count("case") != 3 || len(rs) != 10 || notSent(rs) != 7 {
		t.Errorf("%d cases sent, %d results, %d not sent", s.count("case"), len(rs), notSent(rs))
	}
	for i, r := range rs {
		if (i < 3) != (r.Outcome != run.NotSent) || i >= 3 && !strings.Contains(r.Reason, "limit") {
			t.Errorf("result %d: %+v", i, r)
		}
	}
	// Only the entry that has cases within the limit gets a closing control.
	if s.count("control") != 3 {
		t.Errorf("%d controls", s.count("control"))
	}
	o.Limit = 0
	if _, _, err := Run(context.Background(), o); err == nil {
		t.Error("a limit of 0 was accepted")
	}
}

func TestRunRefusesBeforeSending(t *testing.T) {
	t.Parallel()
	s := startRemote(t, nil)
	target := remoteTarget(s)
	good := planFor(t, target, "query", 2)

	notAllowed := good[0]
	notAllowed.Path = "/admin"
	withHeader := good[0]
	withHeader.Headers = map[string]string{"Cookie": "a=b"}
	public, err := request(good[0], target.Allow[0], placement{PlaceQuery, "q"}, []byte("ping 8.8.8.8"))
	if err != nil {
		t.Fatal(err)
	}
	repeated := []cases.Case{good[0], good[0]}
	bad := map[string]func(*Options){
		"invalid target":       func(o *Options) { o.Target.Allow = nil },
		"wrong confirm host":   func(o *Options) { o.ConfirmHost = "127.0.0.1" },
		"rps over the ceiling": func(o *Options) { o.RPS = 11 },
		"rps zero":             func(o *Options) { o.RPS = 0 },
		"limit zero":           func(o *Options) { o.Limit = 0 },
		"path not allowed":     func(o *Options) { o.Cases = []cases.Case{notAllowed} },
		"case header":          func(o *Options) { o.Cases = []cases.Case{withHeader} },
		"public host":          func(o *Options) { o.Cases = []cases.Case{public} },
		"repeated case":        func(o *Options) { o.Cases = repeated },
		"bad run tag":          func(o *Options) { o.RunTag = "xyz/" },
	}
	for name, edit := range bad {
		o := options(s, target, good)
		edit(&o)
		if _, _, err := Run(context.Background(), o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if n := s.count(""); n != 0 {
		t.Errorf("%d requests were sent", n)
	}
}

// TestRunSendsOnlyToTheTargetHost checks that every connection goes to the
// target's host, one per request so that no request is retried.
func TestRunSendsOnlyToTheTargetHost(t *testing.T) {
	t.Parallel()
	s := startRemote(t, nil)
	target := remoteTarget(s)
	var dialled []string
	var mu sync.Mutex
	client := NewClient(5 * time.Second)
	tr := client.Transport.(*http.Transport)
	dial := tr.DialContext
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		dialled = append(dialled, addr)
		mu.Unlock()
		return dial(ctx, network, addr)
	}
	o := options(s, target, planFor(t, target, "query", 3))
	o.Client = client
	if _, stop, err := Run(context.Background(), o); err != nil || stop != "" {
		t.Fatal(err, stop)
	}
	for _, addr := range dialled {
		if addr != s.url.Host {
			t.Errorf("dialled %s", addr)
		}
	}
	if len(dialled) != s.count("") {
		t.Errorf("%d connections for %d requests", len(dialled), s.count(""))
	}
}
