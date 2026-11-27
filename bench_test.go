package aegolith_test

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ergasterion-dev/aegolith"
)

// benchHeaders are the headers a browser sends with an API call.
func benchHeaders() http.Header {
	h := http.Header{}
	h.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36")
	h.Set("Accept", "application/json")
	h.Set("Accept-Language", "en-US,en;q=0.9")
	h.Set("Referer", "https://shop.example.com/search")
	h.Set("Cookie", "session=6f1d2c3b4a5e6f708192a3b4c5d6e7f8; theme=dark")
	return h
}

func benchSearchGET() *aegolith.Request {
	return &aegolith.Request{
		Method: "GET", RawPath: "/api/v1/products/search",
		RawQuery:   "q=milk+%26+bread&category=dairy&sort=price&page=2",
		RemoteAddr: "192.0.2.10:40000", Header: benchHeaders(),
	}
}

func benchCartPOST() *aegolith.Request {
	h := benchHeaders()
	h.Set("Content-Type", "application/json")
	return &aegolith.Request{
		Method: "POST", RawPath: "/api/v1/cart/items",
		RemoteAddr: "192.0.2.10:40000", Header: h,
		Body: []byte(`{"product_id":"4b8e2f1a-9c3d-4e5f-8a7b-1c2d3e4f5a6b","qty":2,"note":"Please ring the bell, don't knock. Gate code 1234 & leave at door"}`),
	}
}

// benchLargeJSON is a 500-field order import: 100 items of 5 fields.
func benchLargeJSON() *aegolith.Request {
	var b strings.Builder
	b.WriteString(`{"items":[`)
	for i := range 100 {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"sku":"SKU-%05d","name":"Organic whole milk 1L, pack %d","qty":%d,"price":%d.99,"gift":false}`, i, i, i%5+1, 40+i)
	}
	b.WriteString(`]}`)
	h := benchHeaders()
	h.Set("Content-Type", "application/json")
	return &aegolith.Request{
		Method: "POST", RawPath: "/api/v1/orders/import",
		RemoteAddr: "192.0.2.10:40000", Header: h, Body: []byte(b.String()),
	}
}

// benchFirewalls returns the generic Config and the API-aware corpus policy.
func benchFirewalls(tb testing.TB) []struct {
	name string
	fw   *aegolith.Firewall
} {
	tb.Helper()
	generic, err := aegolith.New(aegolith.Config{})
	if err != nil {
		tb.Fatal(err)
	}
	cfg, err := aegolith.LoadConfig(filepath.Join("testdata", "corpus", "example-api-policy.json"))
	if err != nil {
		tb.Fatal(err)
	}
	api, err := aegolith.New(cfg)
	if err != nil {
		tb.Fatal(err)
	}
	return []struct {
		name string
		fw   *aegolith.Firewall
	}{{"generic", generic}, {"api-aware", api}}
}

func benchInspect(b *testing.B, r *aegolith.Request) {
	for _, f := range benchFirewalls(b) {
		b.Run(f.name, func(b *testing.B) {
			if d := f.fw.Inspect(r); d.Action != aegolith.ActionAllow || d.Err != nil {
				b.Fatalf("benchmark request is not a clean allow: %+v", d)
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(r.RawPath) + len(r.RawQuery) + len(r.Body)))
			for b.Loop() {
				f.fw.Inspect(r)
			}
		})
	}
}

func BenchmarkInspectSearchGET(b *testing.B) { benchInspect(b, benchSearchGET()) }

func BenchmarkInspectCartPOST(b *testing.B) { benchInspect(b, benchCartPOST()) }

func BenchmarkInspectLargeJSON(b *testing.B) { benchInspect(b, benchLargeJSON()) }

// benchXML is a 4 KiB XML order: a declaration, a default namespace and
// items with attributes and text.
func benchXML() *aegolith.Request {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><order xmlns="urn:example:orders" id="A-1001">`)
	for i := 0; b.Len() < 4096-160; i++ {
		fmt.Fprintf(&b, `<item sku="SKU-%05d" qty="%d"><name>Organic whole milk 1L, pack %d</name><price>%d.99</price></item>`, i, i%5+1, i, 40+i)
	}
	b.WriteString(`<note>Please ring the bell, don't knock.</note></order>`)
	h := benchHeaders()
	h.Set("Content-Type", "application/xml")
	return &aegolith.Request{
		Method: "POST", RawPath: "/api/v1/orders/import",
		RemoteAddr: "192.0.2.10:40000", Header: h, Body: []byte(b.String()),
	}
}

// BenchmarkInspectXML inspects benchXML with allow_xml set.
func BenchmarkInspectXML(b *testing.B) {
	fw, err := aegolith.New(aegolith.Config{AllowXML: true})
	if err != nil {
		b.Fatal(err)
	}
	r := benchXML()
	if d := fw.Inspect(r); d.Err != nil || d.Action != aegolith.ActionAllow {
		b.Fatalf("benchmark request is not an allow: %+v", d)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(r.Body)))
	for b.Loop() {
		fw.Inspect(r)
	}
}

// BenchmarkInspectLegitCorpus inspects every request of legit.jsonl in turn
// (ns/op is per request).
func BenchmarkInspectLegitCorpus(b *testing.B) {
	var reqs []*aegolith.Request
	for _, c := range loadCorpus(b, "legit.jsonl", "legit") {
		reqs = append(reqs, c.request(b))
	}
	for _, f := range benchFirewalls(b) {
		b.Run(f.name, func(b *testing.B) {
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				f.fw.Inspect(reqs[i%len(reqs)])
				i++
			}
		})
	}
}

// TestLatencyBudget is the spec's latency budget: p99 under 50 µs per
// legitimate request, one goroutine, for the generic Config and the
// API-aware policy. It cycles through testdata/corpus/legit.jsonl for
// 20,000 timed inspections after a warm-up and logs p50, p99 and max. The
// corpus carries few headers, so the set is also measured with a browser's
// User-Agent, Referer, Accept and Cookie headers added (headers a case sets
// itself are kept); its slowest request costs about 17 µs on an Apple M4
// Pro. The budget is asserted on both sets. It runs only with
// AEGOLITH_PERF=1 (make perf, on a quiet machine) and never under -race.
func TestLatencyBudget(t *testing.T) {
	if os.Getenv("AEGOLITH_PERF") != "1" {
		t.Skip("set AEGOLITH_PERF=1 to run the latency budget")
	}
	if raceSlowdown != 1 {
		t.Skip("latency budget is meaningless under -race")
	}
	const (
		n      = 20000
		warmup = 2000
		budget = 50 * time.Microsecond
	)
	var plain, browser []*aegolith.Request
	for _, c := range loadCorpus(t, "legit.jsonl", "legit") {
		plain = append(plain, c.request(t))
		r := c.request(t)
		for k, v := range benchHeaders() {
			if r.Header.Get(k) == "" {
				r.Header[k] = v
			}
		}
		browser = append(browser, r)
	}
	t.Logf("%s, GOMAXPROCS %d, %d legit requests", runtime.Version(), runtime.GOMAXPROCS(0), len(plain))
	for _, f := range benchFirewalls(t) {
		for _, set := range []struct {
			name string
			reqs []*aegolith.Request
		}{{"corpus", plain}, {"+browser headers", browser}} {
			reqs := set.reqs
			for i := range warmup {
				f.fw.Inspect(reqs[i%len(reqs)])
			}
			lat := make([]time.Duration, n)
			for i := range n {
				r := reqs[i%len(reqs)]
				start := time.Now()
				d := f.fw.Inspect(r)
				lat[i] = time.Since(start)
				if d.Action == aegolith.ActionBlock || d.Err != nil {
					t.Fatalf("%s %s: legit request %d blocked or failed: %+v", f.name, set.name, i%len(reqs), d)
				}
			}
			slices.Sort(lat)
			p50, p99, worst := lat[n/2], lat[n*99/100], lat[n-1]
			t.Logf("%-9s %-17s p50 %8v  p99 %8v  max %9v  (budget p99 < %v)", f.name, set.name, p50, p99, worst, budget)
			if p99 >= budget {
				t.Errorf("%s %s: p99 %v, budget %v", f.name, set.name, p99, budget)
			}
		}
	}
}

// worstCaseBodies are in-limit (at most 1 MiB) bodies that drive the
// per-request scan budget (8 x (MaxBodyBytes + 256 KiB) + 64 KiB) as hard
// as it goes: invalid UTF-8 the JSON decoder expands to U+FFFD (1 -> 3
// bytes) and then rescans raw, and tag-dense text that is the slowest
// input for the detectors per byte.
func worstCaseBodies() []struct{ name, body string } {
	const sqli = `"1' OR '1'='1"`
	ff := strings.Repeat("\xff<", (1<<20-200)/2)
	tags := strings.Repeat("<a ", (1<<20-200)/3)
	return []struct{ name, body string }{
		{"ff-lt-trailing-sqli", `["` + ff + `"] ` + sqli},
		{"tags-trailing-sqli", `["` + tags + `"] ` + sqli},
		{"tags-value", `{"a":"` + tags + `"}`},
	}
}

// BenchmarkInspectWorstCase measures the CPU and allocation cost of the
// worst in-limit bodies (generic Config, monitor mode so nothing stops
// early).
func BenchmarkInspectWorstCase(b *testing.B) {
	fw, err := aegolith.New(aegolith.Config{Mode: aegolith.ModeMonitor})
	if err != nil {
		b.Fatal(err)
	}
	for _, c := range worstCaseBodies() {
		if len(c.body) > 1<<20 {
			b.Fatalf("%s: %d bytes", c.name, len(c.body))
		}
		h := http.Header{}
		h.Set("Content-Type", "application/json")
		r := &aegolith.Request{Method: "POST", RawPath: "/s", RemoteAddr: "192.0.2.1:1", Header: h, Body: []byte(c.body)}
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(c.body)))
			for b.Loop() {
				fw.Inspect(r)
			}
		})
	}
}
