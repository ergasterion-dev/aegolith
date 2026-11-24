package aegolith_test

import (
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/ergasterion-dev/aegolith"
)

// fuzzInspectBound is the wall-clock limit for one Inspect on a fuzzed
// request, scaled for the race detector. Fuzz inputs are small (the mutator
// rarely grows them past a few KiB), so a legit-sized request costs
// microseconds; 100 ms only trips on a real pathology.
const fuzzInspectBound = 100 * time.Millisecond * raceSlowdown

// FuzzInspect feeds arbitrary methods, paths, queries, content types,
// bodies, cookies and User-Agents through a generic enforce firewall, a
// generic monitor firewall and the API-aware corpus policy. Inspect must
// not panic (a recovered panic surfaces as Decision.Err), must return a
// valid action (never block in monitor mode) and must return within
// fuzzInspectBound (the fastest of up to three runs, so a scheduler
// stall is not reported as a hang). It is seeded with every corpus line.
func FuzzInspect(f *testing.F) {
	for _, file := range []struct{ name, kind string }{{"attacks.jsonl", "attack"}, {"legit.jsonl", "legit"}} {
		for _, c := range loadCorpus(f, file.name, file.kind) {
			r := c.request(f)
			f.Add(r.Method, r.RawPath, r.RawQuery, r.Header.Get("Content-Type"), r.Body,
				r.Header.Get("Cookie"), r.Header.Get("User-Agent"))
		}
	}
	f.Add("POST", "/api/v1/cart/items", "", "multipart/form-data; boundary=x", []byte("--x\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n<script>\r\n--x--\r\n"), "", "")
	f.Add("POST", "/x", "", "application/xml", []byte(`<!DOCTYPE a [<!ENTITY b SYSTEM "file:///etc/passwd">]><a>&b;</a>`), "", "")
	f.Add("GET", "/%2e%2e/%2fetc", "a=%25&b[$ne]=1&__proto__[x]=1", "", []byte(nil), "sid=a; sid=b", "sqlmap/1.0")

	policy, err := aegolith.LoadConfig(filepath.Join("testdata", "corpus", "example-api-policy.json"))
	if err != nil {
		f.Fatal(err)
	}
	type fw struct {
		name    string
		fw      *aegolith.Firewall
		monitor bool
	}
	var fws []fw
	for _, c := range []struct {
		name string
		cfg  aegolith.Config
	}{
		{"generic", aegolith.Config{Mode: aegolith.ModeEnforce, AllowXML: true, InspectHeaders: []string{"X-Fuzz"}}},
		{"monitor", aegolith.Config{Mode: aegolith.ModeMonitor, AllowXML: true}},
		{"api-aware", policy},
	} {
		w, err := aegolith.New(c.cfg)
		if err != nil {
			f.Fatal(err)
		}
		fws = append(fws, fw{c.name, w, c.cfg.Mode == aegolith.ModeMonitor})
	}

	f.Fuzz(func(t *testing.T, method, path, query, contentType string, body []byte, cookie, ua string) {
		h := http.Header{}
		if contentType != "" {
			h.Set("Content-Type", contentType)
		}
		if cookie != "" {
			h.Set("Cookie", cookie)
		}
		if ua != "" {
			h.Set("User-Agent", ua)
			h.Set("X-Fuzz", ua)
		}
		for _, w := range fws {
			r := &aegolith.Request{Method: method, RawPath: path, RawQuery: query, RemoteAddr: "192.0.2.1:1", Header: h, Body: body}
			d, el := timedInspect(w.fw, r)
			// A real pathology is deterministic; a scheduler or GC stall
			// among parallel fuzz workers is not. Fail only when the
			// fastest of three runs is over the bound.
			for i := 0; i < 2 && el > fuzzInspectBound; i++ {
				_, again := timedInspect(w.fw, r)
				el = min(el, again)
			}
			if el > fuzzInspectBound {
				t.Fatalf("%s: Inspect took %v (bound %v) on a %d-byte body", w.name, el, fuzzInspectBound, len(body))
			}
			if d.Err != nil {
				t.Fatalf("%s: internal error: %v", w.name, d.Err)
			}
			switch d.Action {
			case aegolith.ActionAllow, aegolith.ActionBlock:
			default:
				t.Fatalf("%s: invalid action %q", w.name, d.Action)
			}
			if w.monitor && d.Action == aegolith.ActionBlock {
				t.Fatalf("%s: blocked in monitor mode: %v", w.name, d.Matches)
			}
			for _, m := range d.Matches {
				if m.RuleID == "" || len(m.Field) > 512 {
					t.Fatalf("%s: bad match %+v", w.name, m)
				}
			}
		}
	})
}

func timedInspect(fw *aegolith.Firewall, r *aegolith.Request) (aegolith.Decision, time.Duration) {
	start := time.Now()
	d := fw.Inspect(r)
	return d, time.Since(start)
}
