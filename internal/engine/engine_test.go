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

// TestQueryLineBreakCmdI: a line break in the query string can only arrive
// percent-encoded, so a bare command after it ("x%0aid") is flagged, while
// the same text in a form or JSON body (a textarea, a multi-line note)
// keeps the strict line-break rule.
func TestQueryLineBreakCmdI(t *testing.T) {
	cmdi := func(d model.Decision) bool {
		for _, m := range d.Matches {
			if m.Category == model.CatCmdi {
				return true
			}
		}
		return false
	}
	e := newEngine(t, Options{Mode: model.ModeMonitor, FailOpen: true})
	for _, q := range []string{"q=x%0aid", "q=x%0Awhoami", "q=x%0d%0als", "q=x%0asleep%2010"} {
		if d := e.Inspect(&model.Request{Method: "GET", RawPath: "/a", RawQuery: q, Header: http.Header{}}); !cmdi(d) {
			t.Errorf("query %q: no CmdI match: %+v", q, d.Matches)
		}
	}
	for _, tc := range []struct{ ct, body string }{
		{"application/x-www-form-urlencoded", "note=Notes%3A%0D%0Als"},
		{"application/x-www-form-urlencoded", "note=Notes%3A%0Aid%0AThanks"},
		{"application/json", `{"note":"Notes:\nls"}`},
	} {
		req := &model.Request{Method: "POST", RawPath: "/a", Header: http.Header{"Content-Type": {tc.ct}}, Body: []byte(tc.body)}
		if d := e.Inspect(req); cmdi(d) {
			t.Errorf("body %q: CmdI match: %+v", tc.body, d.Matches)
		}
	}
}
