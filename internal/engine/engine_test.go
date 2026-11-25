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

// TestKeyNames: key names are inspected for SQL injection (field names the
// key, no snippet) in JSON, query, urlencoded and multipart bodies, and a
// query or form key that walks to the prototype in bracket or dot form is
// prototype pollution. Legitimate key names stay clean.
func TestKeyNames(t *testing.T) {
	e := newEngine(t, Options{Mode: model.ModeMonitor, FailOpen: true})
	const mp = "multipart/form-data; boundary=XB"
	mpBody := func(name string) string {
		return "--XB\r\nContent-Disposition: form-data; name=\"" + name + "\"\r\n\r\nx\r\n--XB--\r\n"
	}
	get := func(q string) *model.Request {
		return &model.Request{Method: "GET", RawPath: "/a", RawQuery: q, Header: http.Header{}}
	}
	post := func(ct, body string) *model.Request {
		return &model.Request{Method: "POST", RawPath: "/a", Header: http.Header{"Content-Type": {ct}}, Body: []byte(body)}
	}
	find := func(d model.Decision, rule string) (model.Match, bool) {
		for _, m := range d.Matches {
			if m.RuleID == rule {
				return m, true
			}
		}
		return model.Match{}, false
	}
	for _, tc := range []struct {
		name  string
		req   *model.Request
		rule  string
		field string
	}{
		{"json key", post("application/json", `{"1' OR '1'='1":1}`), "AEG-SQLI-001", "body.1' OR '1'='1"},
		{"query key, encoded =", get("1%27%20OR%20%271%27%3D%271=x"), "AEG-SQLI-001", "query.1' OR '1'='1"},
		// Unencoded, the pair splits on the first '=': the key is "1' OR '1'".
		{"query key, raw", get("1'%20OR%20'1'='1=x"), "AEG-SQLI-001", "query.1' OR '1'"},
		{"form key", post("application/x-www-form-urlencoded", "1%27%20OR%20%271%27%3D%271=x"), "AEG-SQLI-001", "form.1' OR '1'='1"},
		{"multipart key", post(mp, mpBody("1' OR '1'='1")), "AEG-SQLI-001", "form.1' OR '1'='1"},
		{"query proto bracket", get("__proto__[isAdmin]=true"), "AEG-PPOLL-001", "query.__proto__[isAdmin]"},
		{"query constructor dot", get("a.constructor.prototype.x=1"), "AEG-PPOLL-001", "query.a.constructor.prototype.x"},
		{"form constructor bracket", post("application/x-www-form-urlencoded", "constructor[prototype][isAdmin]=1"), "AEG-PPOLL-001", "form.constructor[prototype][isAdmin]"},
	} {
		d := e.Inspect(tc.req)
		m, ok := find(d, tc.rule)
		if !ok {
			t.Errorf("%s: no %s: %+v", tc.name, tc.rule, d.Matches)
			continue
		}
		if m.Field != tc.field {
			t.Errorf("%s: field %q, want %q", tc.name, m.Field, tc.field)
		}
		if tc.rule == "AEG-SQLI-001" && m.Snippet != "" {
			t.Errorf("%s: snippet %q, want none", tc.name, m.Snippet)
		}
	}
	legit := []string{"first name", "user's note", "amount[$USD]", "constructor_year", "prototype_id",
		"filter[constructor]", "item[prototype]", "O'Brien", "rock 'n' roll", "say \"hi\""}
	for _, k := range legit {
		enc := strings.NewReplacer(" ", "%20", "'", "%27", "\"", "%22", "[", "%5B", "]", "%5D", "$", "%24").Replace(k)
		for _, req := range []*model.Request{
			get(enc + "=x"),
			post("application/x-www-form-urlencoded", enc+"=x"),
			post(mp, mpBody(k)),
			post("application/json", `{"`+strings.ReplaceAll(k, `"`, `\"`)+`":"x"}`),
		} {
			if d := e.Inspect(req); len(d.Matches) != 0 {
				t.Errorf("legit key %q (%s): %+v", k, req.Header.Get("Content-Type"), d.Matches)
			}
		}
	}
	// A plain constructor or prototype key is an ordinary query or form
	// field (JSONKey still flags it as a JSON object key).
	for _, q := range []string{"constructor=x", "prototype=x"} {
		if d := e.Inspect(get(q)); len(d.Matches) != 0 {
			t.Errorf("query %q: %+v", q, d.Matches)
		}
	}
	// A quoted key with prose in its value: the whole-pair check stays clean.
	for _, q := range []string{
		"user%27s%20note=I%27m%20fine%2C%201%20or%202%20is%20ok",
		"O%27Brien=Tom%27s%20order%3D2%20and%20Sam%27s",
		"rock%20%27n%27%20roll=it%27s%20%271%27%20or%20%272%27",
		"guest%27s+note=1+or+2",
		"it%27s+size=5+or+6",
		"driver%27s+licence=yes+or+no",
		// The key ends with a quote but the value does not start with one:
		// "'quoted'=1 or 2" reads as SQL only as a whole pair.
		"%27quoted%27=1+or+2",
		"%27quoted%27=10+and+20",
	} {
		if d := e.Inspect(get(q)); len(d.Matches) != 0 {
			t.Errorf("query %q: %+v", q, d.Matches)
		}
	}
	// The pair check still catches quote-split injections.
	for _, q := range []string{"1'%20OR%20'1'='1=x", "x'%20OR%20'a'='a", "1\"%20OR%20\"1\"=\"1"} {
		if _, ok := find(e.Inspect(get(q)), "AEG-SQLI-001"); !ok {
			t.Errorf("query %q: no AEG-SQLI-001", q)
		}
	}
}

// TestLongKeySignal: a key longer than MaxValueLen is scanned only up to
// the cap, so an injection padded past it is not seen; the key still raises
// AEG-PROTO-011 (monitor) on its field, with no snippet.
func TestLongKeySignal(t *testing.T) {
	e := newEngine(t, Options{Mode: model.ModeMonitor, FailOpen: true})
	pad := strings.Repeat("a", model.DefaultLimits().MaxValueLen)
	for _, tc := range []struct {
		name string
		req  *model.Request
	}{
		{"query key", &model.Request{Method: "GET", RawPath: "/a", RawQuery: pad + "%27%20OR%20%271%27%3D%271=x", Header: http.Header{}}},
		{"json key", &model.Request{Method: "POST", RawPath: "/a", Header: http.Header{"Content-Type": {"application/json"}},
			Body: []byte(`{"` + pad + `' OR '1'='1":1}`)}},
	} {
		d := e.Inspect(tc.req)
		n := 0
		for _, m := range d.Matches {
			if m.RuleID == "AEG-PROTO-011" {
				n++
				if m.Snippet != "" || m.Action != model.ActionMonitor || !strings.Contains(m.Field, "aaaa") {
					t.Errorf("%s: %+v", tc.name, m)
				}
			}
		}
		if n != 1 {
			t.Errorf("%s: %d AEG-PROTO-011 matches, want 1: %+v", tc.name, n, d.Matches)
		}
	}
	// A key at the cap is not reported.
	d := e.Inspect(&model.Request{Method: "GET", RawPath: "/a", RawQuery: pad + "=x", Header: http.Header{}})
	if len(d.Matches) != 0 {
		t.Errorf("key at the cap: %+v", d.Matches)
	}
}
