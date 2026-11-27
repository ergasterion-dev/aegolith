package aegolith_test

import (
	"net/http"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/ergasterion-dev/aegolith"
)

// fuzzInspectBound is the wall-clock limit for one Inspect on a fuzzed
// request: 100 ms with AEGOLITH_PERF=1, otherwise 2 s (see wallLimit),
// scaled for -race. The brief's 100 ms is kept only for AEGOLITH_PERF=1:
// make fuzz-quick runs 14 fuzz workers at once, and on a busy machine a
// scheduler stall alone can pass 100 ms. Fuzz inputs are small (the mutator rarely grows them
// past a few KiB), so a legit-sized request costs microseconds; the bound
// only trips on a real pathology. Not checked under -short.
var fuzzInspectBound = wallLimit(100*time.Millisecond, 2*time.Second)

// FuzzInspect feeds arbitrary methods, paths, queries, content types,
// bodies, cookies and User-Agents through a generic enforce firewall, a
// generic monitor firewall and the API-aware corpus policy (the generic
// enforce one declares one route with base64 and base64url fields, so the
// decode path is fuzzed too). Inspect must
// not panic (a recovered panic surfaces as Decision.Err), must return a
// valid action (never block in monitor mode), must be deterministic (a
// second inspection of an identical, independently built request gives the
// same decision apart from Duration) and must return within
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
	// The generic firewall's base64 route. Enforce stops at the first
	// block, so the first seed passes and has every field decoded; the
	// others hold attacks in the path, a JSON body and a form.
	f.Add("POST", "/b64/bm90ZXM", "std=Tm90ZXM6CmxzCg&url=bm90ZXM", "application/json",
		[]byte(`{"std":"TGVhdmUgYXQgdGhlIGRlc2su","url":"bm90ZXM"}`), "", "")
	f.Add("POST", "/b64/PHNjcmlwdD4", "", "", []byte(nil), "", "")
	f.Add("POST", "/b64/bm90ZXM", "", "application/json",
		[]byte(`{"std":"MScgVU5JT04gU0VMRUNUIDEtLQ==","url":"Li4vLi4vZXRjL3Bhc3N3ZA"}`), "", "")
	f.Add("POST", "/b64/bm90ZXM", "", "application/x-www-form-urlencoded",
		[]byte("std=PD9waHA&url=JHtqbmRpOmxkYXA6Ly94L2F9"), "", "")

	policy, err := aegolith.LoadConfig(filepath.Join("testdata", "corpus", "example-api-policy.json"))
	if err != nil {
		f.Fatal(err)
	}
	type fw struct {
		name    string
		fw      *aegolith.Firewall
		monitor bool
	}
	encoded := map[string]aegolith.Field{
		"std": {Type: aegolith.TypeBase64},
		"url": {Type: aegolith.TypeBase64URL},
	}
	base64Route := aegolith.Route{Method: "POST", Path: "/b64/:id",
		PathParams: map[string]aegolith.Field{"id": {Type: aegolith.TypeBase64URL}},
		Query:      encoded, Body: encoded}
	var fws []fw
	for _, c := range []struct {
		name string
		cfg  aegolith.Config
	}{
		{"generic", aegolith.Config{Mode: aegolith.ModeEnforce, AllowXML: true, InspectHeaders: []string{"X-Fuzz"},
			Routes: []aegolith.Route{base64Route}}},
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
			// An independent copy, built before the first inspection.
			r2 := &aegolith.Request{Method: method, RawPath: path, RawQuery: query, RemoteAddr: "192.0.2.1:1", Header: h.Clone(), Body: slices.Clone(body)}
			d, el := timedInspect(w.fw, r)
			// A real pathology is deterministic; a scheduler or GC stall
			// among parallel fuzz workers is not. Fail only when the
			// fastest of three runs is over the bound.
			for i := 0; i < 2 && el > fuzzInspectBound; i++ {
				_, again := timedInspect(w.fw, r)
				el = min(el, again)
			}
			if !testing.Short() && el > fuzzInspectBound {
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
			// Determinism: same config, same request, same decision. The
			// second request shares nothing with the first, so a decision
			// that depended on map order or on mutating its input shows.
			d2 := w.fw.Inspect(r2)
			d.Duration, d2.Duration = 0, 0
			if !reflect.DeepEqual(d, d2) {
				t.Fatalf("%s: nondeterministic decision:\n first %+v\nsecond %+v", w.name, d, d2)
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
