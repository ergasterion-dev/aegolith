package target

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ergasterion-dev/aegolith"
	"github.com/ergasterion-dev/aegolith/bench/internal/records"
)

// attack is a SQL injection the generic detectors block.
const attack = "/x?q=1%27%20OR%20%271%27%3D%271"

const examplePolicy = "../../../testdata/corpus/example-api-policy.json"

type logs struct{ access, decisions bytes.Buffer }

func newHandler(t *testing.T, mode aegolith.Mode, policy string) (http.Handler, *logs) {
	t.Helper()
	l := &logs{}
	h, err := Handler(Config{
		Mode:       mode,
		PolicyPath: policy,
		Access:     records.NewWriter(&l.access),
		Decisions:  records.NewWriter(&l.decisions),
	})
	if err != nil {
		t.Fatal(err)
	}
	return h, l
}

func send(h http.Handler, r *http.Request, id string) *httptest.ResponseRecorder {
	if id != "" {
		r.Header.Set("X-Request-Id", id)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func get(h http.Handler, path, id string) *httptest.ResponseRecorder {
	return send(h, httptest.NewRequest(http.MethodGet, path, nil), id)
}

func (l *logs) read(t *testing.T) (map[string]records.Access, map[string][]records.Decision) {
	t.Helper()
	access, badAccess, err := records.ReadAccess(bytes.NewReader(l.access.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	decisions, badDecisions, err := records.ReadDecisions(bytes.NewReader(l.decisions.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if badAccess != 0 || badDecisions != 0 {
		t.Fatalf("bad lines: access %d, decisions %d", badAccess, badDecisions)
	}
	return access, decisions
}

func TestEnforceBlocksAndRecords(t *testing.T) {
	t.Parallel()
	h, l := newHandler(t, aegolith.ModeEnforce, "")
	before := time.Now()
	if w := get(h, attack, "t1"); w.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", w.Code)
	}
	access, decisions := l.read(t)
	a, ok := access["t1"]
	if !ok || a.Method != http.MethodGet || a.Path != "/x" {
		t.Errorf("access = %+v, %v; want GET /x", a, ok)
	}
	if a.Time.Before(before.Add(-time.Second)) || a.Time.After(time.Now()) {
		t.Errorf("access time %v is not the arrival time", a.Time)
	}
	if len(decisions["t1"]) != 1 {
		t.Fatalf("decisions = %+v, want one for t1", decisions)
	}
	d := decisions["t1"][0]
	if d.Action != "block" || d.Monitored || len(d.Rules) == 0 || d.Error != "" {
		t.Errorf("decision = %+v, want a block with rules", d)
	}
}

func TestMonitorAllowsAndRecords(t *testing.T) {
	t.Parallel()
	h, l := newHandler(t, aegolith.ModeMonitor, "")
	if w := get(h, attack, "t1"); w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", w.Code)
	}
	access, decisions := l.read(t)
	if _, ok := access["t1"]; !ok {
		t.Error("no access record")
	}
	if len(decisions["t1"]) != 1 {
		t.Fatalf("decisions = %+v, want one for t1", decisions)
	}
	if d := decisions["t1"][0]; d.Action != "allow" || !d.Monitored || len(d.Rules) == 0 {
		t.Errorf("decision = %+v, want a monitored allow with rules", d)
	}
}

func TestCleanRequestHasAccessOnly(t *testing.T) {
	t.Parallel()
	h, l := newHandler(t, aegolith.ModeEnforce, "")
	if w := get(h, "/x?q=apples", "t1"); w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", w.Code)
	}
	access, decisions := l.read(t)
	if _, ok := access["t1"]; !ok {
		t.Error("no access record")
	}
	if len(decisions) != 0 {
		t.Errorf("decisions = %+v, want none", decisions)
	}
}

func TestBackendAnswersEveryMethodAndPath(t *testing.T) {
	t.Parallel()
	h, l := newHandler(t, aegolith.ModeEnforce, "")
	// No router sits in front: a path a ServeMux would redirect is answered
	// as it is.
	for id, r := range map[string]*http.Request{
		"get":    httptest.NewRequest(http.MethodGet, "/a//b", nil),
		"put":    httptest.NewRequest(http.MethodPut, "/anything/at/all", strings.NewReader(`{"a":1}`)),
		"delete": httptest.NewRequest(http.MethodDelete, "/", nil),
	} {
		if r.Body != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		if w := send(h, r, id); w.Code != http.StatusOK {
			t.Errorf("%s: status %d, want 200", id, w.Code)
		}
	}
	if access, _ := l.read(t); len(access) != 3 {
		t.Errorf("%d access records, want 3", len(access))
	}
}

func TestRecordsCarryNoRequestValues(t *testing.T) {
	t.Parallel()
	h, l := newHandler(t, aegolith.ModeMonitor, "")
	r := httptest.NewRequest(http.MethodPost, "/submit?secretquery=1%27%20OR%20%271%27%3D%271",
		strings.NewReader(`{"secretfield":"<script>secretbody()</script>"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("User-Agent", "secretagent sqlmap/1.0")
	r.Header.Set("Cookie", "secretcookie=' OR 1=1 --")
	send(h, r, "t1")
	if _, decisions := l.read(t); len(decisions["t1"]) != 1 {
		t.Fatalf("decisions = %+v, want one", decisions)
	}
	for name, log := range map[string]string{"access": l.access.String(), "decisions": l.decisions.String()} {
		if strings.Contains(log, "secret") || strings.Contains(log, "script") {
			t.Errorf("%s log holds a request value: %s", name, log)
		}
	}
}

func TestRecordedPathIsBounded(t *testing.T) {
	t.Parallel()
	h, l := newHandler(t, aegolith.ModeEnforce, "")
	get(h, "/"+strings.Repeat("a", 4000), "t1")
	access, _ := l.read(t)
	if got := len(access["t1"].Path); got != maxPathLen {
		t.Errorf("path of %d bytes, want %d", got, maxPathLen)
	}
}

// A request without a usable ID cannot be joined, and a free-form header value
// must not reach the logs.
func TestUnjoinableRequestIsNotRecorded(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"no id":         "",
		"too long":      strings.Repeat("a", maxIDLen+1),
		"free text":     "a b",
		"markup":        "<script>",
		"non-ASCII":     "idé",
		"path-like":     "a/b",
		"quoted string": `a"b`,
	}
	for name, id := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h, l := newHandler(t, aegolith.ModeEnforce, "")
			if w := get(h, attack, id); w.Code != http.StatusForbidden {
				t.Errorf("status %d, want 403: the WAF still applies", w.Code)
			}
			if l.access.Len() != 0 || l.decisions.Len() != 0 {
				t.Errorf("recorded: %s%s", l.access.String(), l.decisions.String())
			}
		})
	}
}

func TestLongestIDIsRecorded(t *testing.T) {
	t.Parallel()
	h, l := newHandler(t, aegolith.ModeEnforce, "")
	id := "b0000000-" + strings.Repeat("f", 64) + "._A"
	id += strings.Repeat("0", maxIDLen-len(id))
	get(h, attack, id)
	access, decisions := l.read(t)
	if _, ok := access[id]; !ok || len(decisions[id]) != 1 {
		t.Errorf("access %v, decisions %+v; want records for the id", ok, decisions)
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

// An access record without its decision would read as "passed". When the
// decision cannot be written the access record is withheld, so the case reads
// as unknown.
func TestLostDecisionWithholdsAccessRecord(t *testing.T) {
	t.Parallel()
	var access bytes.Buffer
	h, err := Handler(Config{
		Mode:      aegolith.ModeMonitor,
		Access:    records.NewWriter(&access),
		Decisions: records.NewWriter(brokenWriter{}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if w := get(h, attack, "lost"); w.Code != http.StatusOK {
		t.Errorf("status %d, want 200", w.Code)
	}
	if access.Len() != 0 {
		t.Errorf("access record written although its decision was lost: %s", access.String())
	}
	get(h, "/x?q=apples", "clean")
	if !strings.Contains(access.String(), `"clean"`) {
		t.Errorf("a request with no decision still gets its access record, got %q", access.String())
	}
}

func TestPolicyRoutesApplyWithModeOverridden(t *testing.T) {
	t.Parallel()
	// The example policy says enforce and declares limit as an int up to 100.
	const path = "/api/v1/products?limit=oops"
	for _, tt := range []struct {
		mode      aegolith.Mode
		status    int
		action    string
		monitored bool
	}{
		{aegolith.ModeEnforce, http.StatusForbidden, "block", false},
		{aegolith.ModeMonitor, http.StatusOK, "allow", true},
	} {
		t.Run(tt.mode.String(), func(t *testing.T) {
			t.Parallel()
			h, l := newHandler(t, tt.mode, examplePolicy)
			if w := get(h, path, "t1"); w.Code != tt.status {
				t.Fatalf("status %d, want %d", w.Code, tt.status)
			}
			_, decisions := l.read(t)
			if len(decisions["t1"]) != 1 {
				t.Fatalf("decisions = %+v, want one", decisions)
			}
			d := decisions["t1"][0]
			if d.Action != tt.action || d.Monitored != tt.monitored || d.Route != "GET /api/v1/products" {
				t.Errorf("decision = %+v", d)
			}
			if !slices.ContainsFunc(d.Rules, func(r string) bool { return strings.HasPrefix(r, "AEG-SCHEMA-") }) {
				t.Errorf("rules = %v, want a schema rule from the policy", d.Rules)
			}
		})
	}
}

func TestRulesAreListedOnce(t *testing.T) {
	t.Parallel()
	h, l := newHandler(t, aegolith.ModeMonitor, "")
	const payload = "1%27%20OR%20%271%27%3D%271"
	get(h, "/x?a="+payload+"&b="+payload, "t1")
	_, decisions := l.read(t)
	if len(decisions["t1"]) != 1 {
		t.Fatalf("decisions = %+v, want one", decisions)
	}
	rules := decisions["t1"][0].Rules
	if len(rules) == 0 || !slices.IsSorted(rules) || len(slices.Compact(slices.Clone(rules))) != len(rules) {
		t.Errorf("rules = %v, want distinct sorted rule IDs", rules)
	}
}

func TestHandlerRejectsBadConfig(t *testing.T) {
	t.Parallel()
	w := records.NewWriter(io.Discard)
	tests := map[string]Config{
		"no access writer":   {Decisions: w},
		"no decision writer": {Access: w},
		"missing policy":     {PolicyPath: "testdata/none.json", Access: w, Decisions: w},
		"invalid mode":       {Mode: aegolith.Mode(9), Access: w, Decisions: w},
	}
	for name, cfg := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if h, err := Handler(cfg); err == nil || h != nil {
				t.Errorf("Handler = %v, %v; want an error", h, err)
			}
		})
	}
}

func TestAdminHandler(t *testing.T) {
	t.Parallel()
	h := AdminHandler()
	if w := get(h, "/health", ""); w.Code != http.StatusOK {
		t.Errorf("health status %d, want 200", w.Code)
	}
	w := get(h, "/memstats", "")
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("memstats status %d, type %q", w.Code, w.Header().Get("Content-Type"))
	}
	var stats map[string]uint64
	if err := json.Unmarshal(w.Body.Bytes(), &stats); err != nil {
		t.Fatal(err)
	}
	if len(stats) != 2 || stats["heap_alloc"] == 0 || stats["sys"] == 0 {
		t.Errorf("memstats = %v, want heap_alloc and sys", stats)
	}
	if w := send(h, httptest.NewRequest(http.MethodPost, "/health", nil), ""); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /health status %d, want 405", w.Code)
	}
	if w := get(h, "/other", ""); w.Code != http.StatusNotFound {
		t.Errorf("unknown path status %d, want 404", w.Code)
	}
}
