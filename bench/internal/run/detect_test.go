package run

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ergasterion-dev/aegolith"
	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
	"github.com/ergasterion-dev/aegolith/bench/internal/records"
	"github.com/ergasterion-dev/aegolith/bench/internal/sources/baseline"
	"github.com/ergasterion-dev/aegolith/bench/internal/target"
)

const corpusDir = "../../../testdata/corpus"

func numbered(n int) []cases.Case {
	cs := make([]cases.Case, n)
	for i := range cs {
		cs[i] = cases.Case{ID: fmt.Sprintf("c%d", i), Method: "GET", Path: fmt.Sprintf("/%d", i)}
	}
	return cs
}

func TestDetectSendsEachCaseInOrder(t *testing.T) {
	t.Parallel()
	got := make(chan string, 3)
	base := serveTest(t, func(w http.ResponseWriter, r *http.Request) {
		got <- r.URL.Path + " " + r.Header.Get("X-Request-Id")
		w.WriteHeader(http.StatusTeapot)
	})
	rs := Detect(context.Background(), NewClient(testTimeout), base, numbered(3), "p-", 0)
	if len(rs) != 3 {
		t.Fatalf("%d results, want 3", len(rs))
	}
	for i, r := range rs {
		id := fmt.Sprintf("c%d", i)
		if r.CaseID != id || r.RequestID != "p-"+id || r.Status != http.StatusTeapot {
			t.Errorf("result %d = %+v", i, r)
		}
		if r.Outcome != "" || r.Reason != "" || r.Rules != nil || r.LatencyUS < 0 {
			t.Errorf("result %d is already judged: %+v", i, r)
		}
		if g, want := <-got, fmt.Sprintf("/%d p-%s", i, id); g != want {
			t.Errorf("request %d = %q, want %q", i, g, want)
		}
	}
}

func TestDetectKeepsUnansweredCases(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.NotFoundHandler())
	base := parseURL(t, srv.URL)
	srv.Close() // nothing listens now
	rs := Detect(context.Background(), NewClient(testTimeout), base, numbered(2), "p-", 0)
	if len(rs) != 2 {
		t.Fatalf("%d results, want 2", len(rs))
	}
	for _, r := range rs {
		if r.Status != 0 || r.Outcome != "" || !strings.Contains(r.Reason, "no response") {
			t.Errorf("result = %+v", r)
		}
		if strings.Contains(r.Reason, base.Host) {
			t.Errorf("reason names the target: %q", r.Reason)
		}
	}
}

func TestDetectKeepsToTheRate(t *testing.T) {
	t.Parallel()
	base := serveTest(t, func(http.ResponseWriter, *http.Request) {})
	start := time.Now()
	rs := Detect(context.Background(), NewClient(testTimeout), base, numbered(6), "p-", 50)
	// Five intervals of 20 ms lie between six requests; a ticker can fire a
	// little early after a late one.
	if took := time.Since(start); len(rs) != 6 || took < 90*time.Millisecond {
		t.Errorf("%d results in %v, want 6 over at least 90ms", len(rs), took)
	}
}

func TestDetectStopsWhenCancelled(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var hits atomic.Int32
	base := serveTest(t, func(http.ResponseWriter, *http.Request) {
		hits.Add(1)
		cancel()
	})
	// At one request a second, only cancellation ends the wait quickly.
	start := time.Now()
	rs := Detect(ctx, NewClient(testTimeout), base, numbered(4), "p-", 1)
	if took := time.Since(start); took > 500*time.Millisecond {
		t.Errorf("took %v", took)
	}
	if len(rs) != 4 || hits.Load() != 1 {
		t.Fatalf("%d results, %d requests; want 4 and 1", len(rs), hits.Load())
	}
	for _, r := range rs[1:] {
		if r.Outcome != NotSent || r.Reason == "" || r.Status != 0 {
			t.Errorf("result = %+v, want not-sent", r)
		}
	}
}

// Bytes that are illegal in a request line or a header end as rejected or
// not sent, with a reason, never as passed.
func TestIllegalBytesNeverPass(t *testing.T) {
	t.Parallel()
	var accessLog, decisionLog bytes.Buffer
	handler, err := target.Handler(target.Config{
		Mode:      aegolith.ModeMonitor,
		Access:    records.NewWriter(&accessLog),
		Decisions: records.NewWriter(&decisionLog),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()
	get := func(id, path, query string, headers map[string]string) cases.Case {
		return cases.Case{ID: id, Method: "GET", Path: path, RawQuery: query, Headers: headers}
	}
	cs := []cases.Case{
		get("space-in-path", "/a b", "", nil),
		get("version-in-query", "/a", "q=x HTTP/1.1", nil),
		get("bad-escape", "/%zz", "", nil),
		get("bad-escape-after-slashes", "//%zz", "", nil),
		get("unknown-expect", "/a", "", map[string]string{"Expect": "teapot"}),
		get("newline-in-path", "/a\r\nX: 1", "", nil),
		get("nul-in-header", "/a", "", map[string]string{"X-Note": "\x00"}),
	}
	sent := Detect(context.Background(), NewClient(testTimeout), parseURL(t, srv.URL), cs, "p-", 0)
	srv.Close()
	access, _, err := records.ReadAccess(&accessLog)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range Join(sent, access, nil) {
		want := Rejected
		if i >= 5 {
			want = NotSent
		}
		if r.Outcome != want || r.Reason == "" {
			t.Errorf("%s: %s, status %d, reason %q; want %s", r.CaseID, r.Outcome, r.Status, r.Reason, want)
		}
	}
}

// The whole path: the project's corpus over HTTP against an enforcing target
// with the example policy, judged from the target's logs. net/http answers
// some requests before the firewall, so a rejected attack counts with the
// blocked ones.
func TestDetectAgainstTarget(t *testing.T) {
	t.Parallel()
	lines, err := baseline.Import(corpusDir)
	if err != nil {
		t.Fatal(err)
	}
	var all []cases.Case
	names := map[string]string{}
	for _, l := range lines {
		c, err := cases.FromLine(l)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, c)
		names[c.ID] = l.Category + " / " + l.SourceCaseID
	}
	merged, conflicts := cases.Merge(all)
	if len(conflicts) != 0 {
		t.Fatalf("%d conflicting cases", len(conflicts))
	}

	var accessLog, decisionLog bytes.Buffer
	handler, err := target.Handler(target.Config{
		Mode:       aegolith.ModeEnforce,
		PolicyPath: corpusDir + "/example-api-policy.json",
		Access:     records.NewWriter(&accessLog),
		Decisions:  records.NewWriter(&decisionLog),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	sent := Detect(context.Background(), NewClient(testTimeout), parseURL(t, srv.URL), merged, "t0000000-", 2000)
	srv.Close() // waits for the handlers, so the logs are complete

	access, badAccess, err := records.ReadAccess(&accessLog)
	if err != nil || badAccess != 0 {
		t.Fatalf("access log: %d bad lines, %v", badAccess, err)
	}
	ds, badDecisions, err := records.ReadDecisions(&decisionLog)
	if err != nil || badDecisions != 0 {
		t.Fatalf("decision log: %d bad lines, %v", badDecisions, err)
	}
	rs := Join(sent, access, ds)
	if len(rs) != len(merged) {
		t.Fatalf("%d results for %d cases", len(rs), len(merged))
	}

	attacks, legit := map[Outcome]int{}, map[Outcome]int{}
	for i, r := range rs {
		c := merged[i]
		if r.CaseID != c.ID {
			t.Fatalf("result %d is for another case", i)
		}
		count, usual := legit, Passed
		if c.Expected == cases.Attack {
			count, usual = attacks, Blocked
		}
		count[r.Outcome]++
		if r.Outcome != usual {
			t.Logf("%s %s: %s, status %d, rules %v %s", c.Expected, names[c.ID], r.Outcome, r.Status, r.Rules, r.Reason)
		}
	}
	t.Logf("attacks %v", attacks)
	t.Logf("legit %v", legit)

	if got := attacks[Blocked] + attacks[Rejected]; got < 227 {
		t.Errorf("%d attacks blocked or rejected, want at least 227", got)
	}
	if legit[Blocked] != 0 {
		t.Errorf("%d legitimate cases blocked, want 0", legit[Blocked])
	}
	// The runner must account for every case of the project's own corpus.
	for _, outcome := range []Outcome{Unknown, NotSent} {
		if n := attacks[outcome] + legit[outcome]; n != 0 {
			t.Errorf("%d cases %s, want 0", n, outcome)
		}
	}
	if legit[Rejected] != 0 {
		t.Errorf("%d legitimate cases rejected, want 0", legit[Rejected])
	}
}
