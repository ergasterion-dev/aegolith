package engine

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ergasterion-dev/aegolith/internal/model"
)

func newEngine(t *testing.T, o Options) *Engine {
	t.Helper()
	if o.Limits == (model.Limits{}) {
		o.Limits = model.DefaultLimits()
	}
	e, err := New(o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

func TestInspectPanicFailOpen(t *testing.T) {
	req := &model.Request{Method: "GET", RawPath: "/a", Header: http.Header{}}
	for _, tc := range []struct {
		failOpen bool
		want     model.Action
	}{{true, model.ActionAllow}, {false, model.ActionBlock}} {
		e := newEngine(t, Options{FailOpen: tc.failOpen})
		e.testHook = func(*model.Request) { panic("boom\nsecret=" + strings.Repeat("x", 200)) }
		d := e.Inspect(req)
		if d.Action != tc.want || d.Err == nil || d.Monitored || len(d.Matches) != 0 {
			t.Fatalf("failOpen=%v: %+v", tc.failOpen, d)
		}
		if msg := d.Err.Error(); strings.Contains(msg, "\n") || len(msg) > 128 {
			t.Fatalf("error message not redacted: %q", msg)
		}
	}
	// A runtime error panic (nil map write, index out of range) is caught too.
	e := newEngine(t, Options{FailOpen: true})
	e.testHook = func(*model.Request) {
		var m map[string]int
		m["x"] = 1
	}
	if d := e.Inspect(req); d.Action != model.ActionAllow || d.Err == nil {
		t.Fatalf("runtime panic: %+v", d)
	}
}

func TestPattern(t *testing.T) {
	for _, tc := range []struct {
		pat, v string
		want   bool
	}{
		{"", "anything", true},
		{"*", "anything", true},
		{"AEG-SQLI-*", "AEG-SQLI-001", true},
		{"AEG-SQLI-*", "AEG-SSRF-001", false},
		{"AEG-SQLI-001", "AEG-SQLI-001", true},
		{"AEG-SQLI-001", "AEG-SQLI-0011", false},
		{"query.*", "query.q", true},
		{"query.q", "query.qq", false},
	} {
		if got := matchPattern(tc.pat, tc.v); got != tc.want {
			t.Errorf("matchPattern(%q,%q) = %v", tc.pat, tc.v, got)
		}
	}
}

func TestLimitPairs(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		n    int
		want string
		over bool
	}{
		{"", 3, "", false},
		{"a=1&b=2&c=3", 3, "a=1&b=2&c=3", false},
		{"a=1&b=2&c=3&d=4", 3, "a=1&b=2&c=3", true},
		{"a=1&&b=2&&&c=3&&", 3, "a=1&&b=2&&&c=3&&", false},
		{"a=1&&b=2&&c=3&&d", 3, "a=1&&b=2&&c=3", true},
		{"&&&a", 1, "&&&a", false},
		{"a&b", 0, "", true},
	} {
		got, over := limitPairs(tc.raw, tc.n)
		if got != tc.want || over != tc.over {
			t.Errorf("limitPairs(%q,%d) = %q,%v want %q,%v", tc.raw, tc.n, got, over, tc.want, tc.over)
		}
	}
}

func TestCanonicalHeaderDeterministic(t *testing.T) {
	h := http.Header{"x-a": {"1"}, "X-A": {"2"}, "X-a": {"3"}}
	want := canonicalHeader(h)
	if len(want["X-A"]) != 3 {
		t.Fatalf("merged %v", want)
	}
	for range 100 {
		got := canonicalHeader(h)
		if strings.Join(got["X-A"], ",") != strings.Join(want["X-A"], ",") {
			t.Fatalf("order changed: %v vs %v", got, want)
		}
	}
	if canonicalHeader(nil) == nil {
		t.Fatal("nil header should become empty, not nil")
	}
}

// TestEarlyStopEnforce: in enforce mode inspection stops at the first
// blocking match; in monitor mode every match is reported.
func TestEarlyStopEnforce(t *testing.T) {
	req := &model.Request{Method: "GET", RawPath: "/a", RawQuery: "a=1%27%20OR%20%271%27%3D%271&b=%3Cscript%3Ealert(1)%3C/script%3E", Header: http.Header{}}
	e := newEngine(t, Options{FailOpen: true})
	if d := e.Inspect(req); d.Action != model.ActionBlock || len(d.Matches) != 1 {
		t.Fatalf("enforce: %+v", d)
	}
	e = newEngine(t, Options{Mode: model.ModeMonitor, FailOpen: true})
	if d := e.Inspect(req); len(d.Matches) < 2 {
		t.Fatalf("monitor: %+v", d)
	}
}
