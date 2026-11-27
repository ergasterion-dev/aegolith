package run

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ergasterion-dev/aegolith"
	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
	"github.com/ergasterion-dev/aegolith/bench/internal/records"
	"github.com/ergasterion-dev/aegolith/bench/internal/target"
)

// loadCases returns n attack cases on /attack/i and n legitimate ones on
// /legit/i.
func loadCases(n int) []cases.Case {
	var cs []cases.Case
	for i := range n {
		cs = append(cs,
			cases.Case{ID: fmt.Sprintf("a%d", i), Expected: cases.Attack, Method: "GET", Path: fmt.Sprintf("/attack/%d", i)},
			cases.Case{ID: fmt.Sprintf("l%d", i), Expected: cases.Legit, Method: "GET", Path: fmt.Sprintf("/legit/%d", i)})
	}
	return cs
}

// counter counts the requests a test server gets by the first path segment.
type counter struct {
	mu    sync.Mutex
	count map[string]int
}

func (c *counter) handle(_ http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.count == nil {
		c.count = map[string]int{}
	}
	c.count[strings.SplitN(r.URL.Path, "/", 3)[1]]++
}

func (c *counter) of(segment string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count[segment]
}

func TestLoadRespectsRate(t *testing.T) {
	t.Parallel()
	var seen counter
	base := serveTest(t, seen.handle)
	res, err := Load(context.Background(), NewLoadClient(testTimeout, 16), LoadOptions{
		Base: base, Cases: loadCases(5), RPS: 100, Workers: 16, Duration: 2 * time.Second, AttackShare: 0.1, Seed: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Sent < 150 || res.Sent > 220 {
		t.Errorf("sent %d requests in 2 s at 100 per second, want 150 to 220", res.Sent)
	}
	// The schedule has exactly 200 places: each was sent or is counted as dropped.
	if res.Sent+res.Dropped != 200 {
		t.Errorf("sent %d + dropped %d, want the 200 of the schedule", res.Sent, res.Dropped)
	}
	if got := seen.of("attack") + seen.of("legit"); got != res.Sent {
		t.Errorf("the target saw %d requests, the result says %d", got, res.Sent)
	}
	if res.ByStatus[http.StatusOK] != res.Sent || res.TransportErrors != 0 || res.Interrupted {
		t.Errorf("result = %+v, want every request answered 200", res)
	}
	if res.Duration < 2*time.Second || res.Duration > 2*time.Second+testTimeout {
		t.Errorf("duration = %v, want the 2 s asked for", res.Duration)
	}
	if want := float64(res.Sent) / res.Duration.Seconds(); res.AchievedRPS != want || res.AchievedRPS > 100 {
		t.Errorf("achieved %v per second, want sent over duration = %v", res.AchievedRPS, want)
	}
	if res.P50US <= 0 || res.P50US > res.P90US || res.P90US > res.P99US || res.P99US > res.MaxUS {
		t.Errorf("percentiles %d, %d, %d, max %d are not in order", res.P50US, res.P90US, res.P99US, res.MaxUS)
	}
	if res.RPS != 100 || res.Workers != 16 || res.AttackShare != 0.1 || res.Seed != 1 ||
		res.AttackCases != 5 || res.LegitCases != 5 {
		t.Errorf("result does not say what was asked: %+v", res)
	}
}

func TestLoadAttackShare(t *testing.T) {
	t.Parallel()
	var seen counter
	base := serveTest(t, seen.handle)
	res, err := Load(context.Background(), NewLoadClient(testTimeout, 256), LoadOptions{
		Base: base, Cases: loadCases(20), RPS: 1000, Workers: 256, Duration: time.Second, AttackShare: 0.2, Seed: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Sent+res.Dropped != 1000 {
		t.Fatalf("sent %d + dropped %d, want the 1000 of the schedule", res.Sent, res.Dropped)
	}
	// 150 to 250 of 1000, scaled should a busy machine have dropped ticks.
	low, high := res.Sent*150/1000, res.Sent*250/1000
	if res.Attacks < low || res.Attacks > high {
		t.Errorf("%d of %d requests were attacks, want %d to %d", res.Attacks, res.Sent, low, high)
	}
	if got := seen.of("attack"); got != res.Attacks {
		t.Errorf("the target saw %d attacks, the result says %d", got, res.Attacks)
	}
	if got := seen.of("legit"); got != res.Sent-res.Attacks {
		t.Errorf("the target saw %d legitimate requests, want %d", got, res.Sent-res.Attacks)
	}
}

func TestLoadSelectionIsSeeded(t *testing.T) {
	t.Parallel()
	pools := func(cs []cases.Case) loadPools {
		t.Helper()
		p, err := newLoadPools(LoadOptions{Base: parseURL(t, "http://127.0.0.1:1"), Cases: cs, AttackShare: 0.2})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	draw := func(p loadPools, share float64, seed int64) (ids []string, attacks int) {
		pick := newPicker(p, share, seed)
		for range 1000 {
			c, attack := pick.next()
			if attack != (c.Expected == cases.Attack) {
				t.Fatalf("case %s drawn as attack=%t", c.ID, attack)
			}
			if attack {
				attacks++
			}
			ids = append(ids, c.ID)
		}
		return ids, attacks
	}
	p := pools(loadCases(30))
	first, attacks := draw(p, 0.2, 5)
	if attacks < 150 || attacks > 250 {
		t.Errorf("%d of 1000 draws are attacks at a share of 0.2, want 150 to 250", attacks)
	}
	if again, _ := draw(pools(loadCases(30)), 0.2, 5); fmt.Sprint(again) != fmt.Sprint(first) {
		t.Error("the same seed and cases gave another sequence")
	}
	if other, _ := draw(p, 0.2, 6); fmt.Sprint(other) == fmt.Sprint(first) {
		t.Error("another seed gave the same sequence")
	}
	distinct := map[string]bool{}
	for _, id := range first {
		distinct[id] = true
	}
	if len(distinct) < 50 {
		t.Errorf("1000 draws used %d of 60 cases", len(distinct))
	}
	if _, attacks := draw(p, 0, 5); attacks != 0 {
		t.Errorf("%d attacks at a share of 0", attacks)
	}
	if _, attacks := draw(p, 1, 5); attacks != 1000 {
		t.Errorf("%d attacks at a share of 1, want 1000", attacks)
	}
}

func TestLoadStopsOnContextCancel(t *testing.T) {
	t.Parallel()
	const workers = 8
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var arrived, released atomic.Int64
	var cancelled time.Time
	base := serveTest(t, func(_ http.ResponseWriter, r *http.Request) {
		// Cancelled once every worker is held, so that the requests in flight
		// are known whatever the machine is doing.
		if arrived.Add(1) == workers {
			cancelled = time.Now()
			cancel()
		}
		// Never answers: the request ends when the client lets go of it.
		<-r.Context().Done()
		released.Add(1)
	})
	res, err := Load(ctx, NewLoadClient(testTimeout, workers), LoadOptions{
		Base: base, Cases: loadCases(2), RPS: 100, Workers: workers, Duration: 30 * time.Second, Seed: 1,
	})
	took := time.Since(cancelled)
	if err != nil {
		t.Fatalf("a cancelled run is an error, want its partial result: %v", err)
	}
	if took > time.Second {
		t.Errorf("Load returned %v after the cancel, want under 1 s", took)
	}
	if !res.Interrupted {
		t.Error("the result is not marked as interrupted")
	}
	if res.Cancelled != workers || res.Sent != 0 || res.TransportErrors != 0 {
		t.Errorf("cancelled %d, sent %d, transport errors %d; want the %d requests in flight as cancelled only",
			res.Cancelled, res.Sent, res.TransportErrors, workers)
	}
	if res.Duration <= 0 || res.Duration >= 30*time.Second {
		t.Errorf("duration = %v, want the time until the cancel", res.Duration)
	}
	// Nothing of the run is left: the target sees every request let go.
	deadline := time.Now().Add(testTimeout)
	for released.Load() != arrived.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if released.Load() != arrived.Load() || int(arrived.Load()) != res.Cancelled {
		t.Errorf("%d requests arrived and %d were let go, %d were cancelled; want the same number",
			arrived.Load(), released.Load(), res.Cancelled)
	}
}

func TestLoadDropsTicksWhenWorkersAreBusy(t *testing.T) {
	t.Parallel()
	base := serveTest(t, func(http.ResponseWriter, *http.Request) { time.Sleep(100 * time.Millisecond) })
	res, err := Load(context.Background(), NewLoadClient(testTimeout, 2), LoadOptions{
		Base: base, Cases: loadCases(2), RPS: 100, Workers: 2, Duration: 500 * time.Millisecond, AttackShare: 0.5, Seed: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Sent+res.Dropped != 50 {
		t.Errorf("sent %d + dropped %d, want the 50 of the schedule", res.Sent, res.Dropped)
	}
	// Two workers and 100 ms per answer: about 10 requests fit in 500 ms. The
	// bounds leave room for a machine that stalls the schedule.
	if res.Sent < 2 || res.Dropped < 25 {
		t.Errorf("sent %d, dropped %d; want about 10 sent and the rest dropped", res.Sent, res.Dropped)
	}
	if res.AchievedRPS >= 50 {
		t.Errorf("achieved %v per second with most ticks dropped", res.AchievedRPS)
	}
	// The round trip of what was sent is not hidden by the drops.
	if res.P50US < 100_000 {
		t.Errorf("p50 = %d us, want the 100 ms the target takes", res.P50US)
	}
}

func TestLoadRefusesBeforeSending(t *testing.T) {
	t.Parallel()
	var requests atomic.Int64
	base := serveTest(t, func(http.ResponseWriter, *http.Request) { requests.Add(1) })
	onlyAttacks, onlyLegit := loadCases(2)[:1], loadCases(2)[1:2]
	nearMiss := []cases.Case{{ID: "n", Expected: cases.NearMiss, Method: "GET", Path: "/near"}}
	unsendable := cases.Case{ID: "u", Expected: cases.Attack, Method: "GET", Path: "no-slash"}
	good := LoadOptions{Base: base, Cases: loadCases(2), RPS: 10, Workers: 1, Duration: time.Second, AttackShare: 0.5}
	with := func(change func(*LoadOptions)) LoadOptions {
		o := good
		change(&o)
		return o
	}
	nan := 0.0
	nan /= nan
	tests := map[string]LoadOptions{
		"no base":                  with(func(o *LoadOptions) { o.Base = nil }),
		"base without a host":      with(func(o *LoadOptions) { o.Base = &url.URL{Scheme: "http"} }),
		"admin without a host":     with(func(o *LoadOptions) { o.AdminURL = &url.URL{Scheme: "http"} }),
		"no rate":                  with(func(o *LoadOptions) { o.RPS = 0 }),
		"a rate beyond the clock":  with(func(o *LoadOptions) { o.RPS = MaxLoadRPS + 1 }),
		"no workers":               with(func(o *LoadOptions) { o.Workers = 0 }),
		"too many workers":         with(func(o *LoadOptions) { o.Workers = MaxLoadWorkers + 1 }),
		"no duration":              with(func(o *LoadOptions) { o.Duration = 0 }),
		"a duration without ticks": with(func(o *LoadOptions) { o.Duration = time.Millisecond }),
		"negative share":           with(func(o *LoadOptions) { o.AttackShare = -0.1 }),
		"share above one":          with(func(o *LoadOptions) { o.AttackShare = 1.1 }),
		"share not a number":       with(func(o *LoadOptions) { o.AttackShare = nan }),
		"no cases":                 with(func(o *LoadOptions) { o.Cases = nil }),
		"attacks wanted, none":     with(func(o *LoadOptions) { o.Cases = onlyLegit }),
		"legit wanted, none":       with(func(o *LoadOptions) { o.Cases = onlyAttacks }),
		"all legit wanted, none":   with(func(o *LoadOptions) { o.Cases, o.AttackShare = onlyAttacks, 0 }),
		"all attacks wanted, none": with(func(o *LoadOptions) { o.Cases, o.AttackShare = onlyLegit, 1 }),
		"near-miss is not legit":   with(func(o *LoadOptions) { o.Cases = append(nearMiss, onlyAttacks...) }),
		"the only attack cannot be sent": with(func(o *LoadOptions) {
			o.Cases = append([]cases.Case{unsendable}, onlyLegit...)
		}),
	}
	for name, o := range tests {
		if _, err := Load(context.Background(), NewLoadClient(testTimeout, 1), o); err == nil {
			t.Errorf("%s: no error", name)
		} else if strings.Contains(err.Error(), "no-slash") {
			t.Errorf("%s: the error repeats a request value: %v", name, err)
		}
	}
	if n := requests.Load(); n != 0 {
		t.Errorf("%d requests were sent by refused runs", n)
	}
}

// TestLoadUsesOnlySendableAttackAndLegitCases also covers a pool that is not
// needed: a share of 0 or 1 does not need the other kind.
func TestLoadUsesOnlySendableAttackAndLegitCases(t *testing.T) {
	t.Parallel()
	var seen counter
	base := serveTest(t, seen.handle)
	cs := append(loadCases(3),
		cases.Case{ID: "n", Expected: cases.NearMiss, Method: "GET", Path: "/near/1"},
		cases.Case{ID: "u1", Expected: cases.Attack, Method: "GET", Path: "no-slash"},
		cases.Case{ID: "u2", Expected: cases.Legit, Method: "BAD METHOD", Path: "/unsendable/1"},
		cases.Case{ID: "u3", Expected: cases.NearMiss, Method: "GET", Path: "no-slash-near"})
	res, err := Load(context.Background(), NewLoadClient(testTimeout, 8), LoadOptions{
		Base: base, Cases: cs, RPS: 400, Workers: 8, Duration: 250 * time.Millisecond, AttackShare: 0.5, Seed: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.AttackCases != 3 || res.LegitCases != 3 || res.Excluded != 2 {
		t.Errorf("pools of %d attack and %d legit cases, %d excluded; want 3, 3 and the 2 that cannot be sent",
			res.AttackCases, res.LegitCases, res.Excluded)
	}
	if res.Sent+res.Dropped != 100 || res.NotSent != 0 || res.TransportErrors != 0 {
		t.Errorf("sent %d, dropped %d, not sent %d, transport errors %d; want the 100 of the schedule and no refusals",
			res.Sent, res.Dropped, res.NotSent, res.TransportErrors)
	}
	if seen.of("near") != 0 || seen.of("unsendable") != 0 || seen.of("attack")+seen.of("legit") != res.Sent {
		t.Errorf("the target saw %v, want attack and legit cases only", seen.count)
	}

	for share, segment := range map[float64]string{0: "legit", 1: "attack"} {
		var seen counter
		base := serveTest(t, seen.handle)
		only := []cases.Case{{ID: "x", Expected: cases.Expected(segment), Method: "GET", Path: "/" + segment + "/1"}}
		res, err := Load(context.Background(), NewLoadClient(testTimeout, 4), LoadOptions{
			Base: base, Cases: only, RPS: 100, Workers: 4, Duration: 100 * time.Millisecond, AttackShare: share,
		})
		if err != nil {
			t.Errorf("share %v with only %s cases: %v", share, segment, err)
			continue
		}
		if res.Sent == 0 || seen.of(segment) != res.Sent {
			t.Errorf("share %v: sent %d, the target saw %v", share, res.Sent, seen.count)
		}
	}
}

// TestLoadIDsAreNotDetectionIDs: a detection request ID ends in a case ID of
// 64 characters, so a shorter ID can be no detection request.
func TestLoadIDsAreNotDetectionIDs(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	ids := map[string]int{}
	base := serveTest(t, func(_ http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		ids[r.Header.Get("X-Request-Id")]++
	})
	res, err := Load(context.Background(), NewLoadClient(testTimeout, 8), LoadOptions{
		Base: base, Cases: loadCases(1), RPS: 400, Workers: 8, Duration: 250 * time.Millisecond, AttackShare: 0.5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != res.Sent || res.Sent == 0 {
		t.Fatalf("%d distinct request IDs for %d requests", len(ids), res.Sent)
	}
	if !strings.HasPrefix(res.IDPrefix, "load-") || strings.HasPrefix(res.IDPrefix, "b0000000-") {
		t.Errorf("ID prefix %q, want one that starts with load-", res.IDPrefix)
	}
	for id := range ids {
		if !strings.HasPrefix(id, res.IDPrefix) || !ValidRequestID(id) || len(id) >= 64 {
			t.Fatalf("request ID %q: want the prefix %q, the target's alphabet and under 64 characters", id, res.IDPrefix)
		}
	}
	// The longest ID a run can use is still shorter than a case ID.
	if longest := loadIDPrefix(time.Unix(0, math.MaxInt64)) + fmt.Sprint(int64(math.MaxInt64)); len(longest) >= 64 || !ValidRequestID(longest) {
		t.Errorf("a load request ID can be %q", longest)
	}
	again, err := Load(context.Background(), NewLoadClient(testTimeout, 8), LoadOptions{
		Base: base, Cases: loadCases(1), RPS: 100, Workers: 8, Duration: 50 * time.Millisecond, AttackShare: 0.5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if again.IDPrefix == res.IDPrefix {
		t.Errorf("two runs share the ID prefix %q", res.IDPrefix)
	}
}

// TestLoadDecidesConnectionReuse: a case may ask for "Connection: close", as
// the CRS cases do, and detection sends that. In the load phase it would make
// every such request open a connection of its own.
func TestLoadDecidesConnectionReuse(t *testing.T) {
	t.Parallel()
	var closing, withHeader, kept atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if r.Close {
			closing.Add(1)
		}
		if r.Header.Get("Connection") != "" {
			withHeader.Add(1)
		}
		if r.Header.Get("X-Kept") == "yes" {
			kept.Add(1)
		}
	}))
	var conns atomic.Int64
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	base := parseURL(t, srv.URL)

	cs := []cases.Case{
		{ID: "a", Expected: cases.Attack, Method: "GET", Path: "/a", Headers: map[string]string{"Connection": "close", "X-Kept": "yes"}},
		{ID: "l", Expected: cases.Legit, Method: "GET", Path: "/l", Headers: map[string]string{"cOnNeCtIoN": "close", "X-Kept": "yes"}},
	}
	// Detection is unchanged: the header goes out.
	if _, _, err := Send(context.Background(), NewClient(testTimeout), base, cs[0], "r1"); err != nil {
		t.Fatal(err)
	}
	if closing.Load() != 1 || withHeader.Load() != 1 {
		t.Fatalf("Send dropped the Connection header of a case")
	}
	closing.Store(0)
	withHeader.Store(0)
	conns.Store(0)
	kept.Store(0)

	res, err := Load(context.Background(), NewLoadClient(testTimeout, 4), LoadOptions{
		Base: base, Cases: cs, RPS: 200, Workers: 4, Duration: 500 * time.Millisecond, AttackShare: 0.5, Seed: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Sent == 0 || res.Excluded != 0 {
		t.Fatalf("sent %d, excluded %d", res.Sent, res.Excluded)
	}
	if closing.Load() != 0 || withHeader.Load() != 0 {
		t.Errorf("%d requests asked to close and %d carried a Connection header, want none", closing.Load(), withHeader.Load())
	}
	if int(kept.Load()) != res.Sent {
		t.Errorf("%d of %d requests kept their other headers", kept.Load(), res.Sent)
	}
	// With the header every request would open a connection. Without it the
	// four workers need four, or a few more when a request starts before the
	// connection of the one before is back in the pool.
	if n := int(conns.Load()); n > 16 && n*2 > res.Sent {
		t.Errorf("%d connections for %d requests of 4 workers, want them reused", n, res.Sent)
	}
	if cs[0].Headers["Connection"] != "close" {
		t.Error("Load changed the headers of the caller's case")
	}
}

func TestLoadCountsTransportErrors(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.NotFoundHandler())
	base := parseURL(t, srv.URL)
	srv.Close() // nothing listens now
	res, err := Load(context.Background(), NewLoadClient(testTimeout, 4), LoadOptions{
		Base: base, Cases: loadCases(1), RPS: 100, Workers: 4, Duration: 200 * time.Millisecond, AttackShare: 0.5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Sent+res.Dropped != 20 || res.TransportErrors != res.Sent || res.Sent == 0 {
		t.Errorf("sent %d, dropped %d, transport errors %d; want every request sent to fail", res.Sent, res.Dropped, res.TransportErrors)
	}
	if len(res.ByStatus) != 0 || res.P50US != 0 || res.MaxUS != 0 || res.Interrupted || res.Cancelled != 0 {
		t.Errorf("result = %+v, want no status and no latency without an answer", res)
	}
}

func TestLoadCountsEveryStatus(t *testing.T) {
	t.Parallel()
	base := serveTest(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/attack"):
			w.WriteHeader(http.StatusForbidden)
		case r.URL.Path == "/legit/0":
			// A redirect is an answer and is not followed.
			http.Redirect(w, r, "http://192.0.2.1/elsewhere", http.StatusFound)
		}
	})
	res, err := Load(context.Background(), NewLoadClient(testTimeout, 8), LoadOptions{
		Base: base, Cases: loadCases(2), RPS: 400, Workers: 8, Duration: 250 * time.Millisecond, AttackShare: 0.5, Seed: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, n := range res.ByStatus {
		total += n
	}
	if total != res.Sent || res.TransportErrors != 0 {
		t.Errorf("statuses add up to %d of %d sent, %d transport errors", total, res.Sent, res.TransportErrors)
	}
	if res.ByStatus[http.StatusForbidden] != res.Attacks || res.ByStatus[http.StatusFound] == 0 || res.ByStatus[http.StatusOK] == 0 {
		t.Errorf("by status = %v with %d attacks", res.ByStatus, res.Attacks)
	}
}

func TestLoadPollsMemory(t *testing.T) {
	t.Parallel()
	base := serveTest(t, func(http.ResponseWriter, *http.Request) {})
	options := func(admin *url.URL) LoadOptions {
		return LoadOptions{
			Base: base, AdminURL: admin, Cases: loadCases(1), RPS: 50, Workers: 4,
			Duration: 500 * time.Millisecond, AttackShare: 0.5, memInterval: 25 * time.Millisecond,
		}
	}
	t.Run("the target's admin endpoint", func(t *testing.T) {
		t.Parallel()
		var polls atomic.Int64
		admin := target.AdminHandler()
		adminURL := serveTest(t, func(w http.ResponseWriter, r *http.Request) {
			polls.Add(1)
			admin.ServeHTTP(w, r)
		})
		res, err := Load(context.Background(), NewLoadClient(testTimeout, 4), options(adminURL))
		if err != nil {
			t.Fatal(err)
		}
		// One at the start, one at the end and those in between: about 20,
		// fewer on a machine that stalls. A reading the end of the run cut
		// short reached the endpoint and is not counted.
		seen := int(polls.Load())
		if !res.MemAsked || res.MemPolls < 3 || seen < res.MemPolls || seen > res.MemPolls+1 || res.MemPollFailures != 0 {
			t.Errorf("%d polls, %d failed, the admin endpoint saw %d", res.MemPolls, res.MemPollFailures, polls.Load())
		}
		if res.HeapStart == 0 || res.HeapEnd == 0 || res.HeapPeak < res.HeapStart || res.HeapPeak < res.HeapEnd {
			t.Errorf("heap start %d, peak %d, end %d", res.HeapStart, res.HeapPeak, res.HeapEnd)
		}
	})
	t.Run("given values", func(t *testing.T) {
		t.Parallel()
		var n atomic.Int64
		adminURL := serveTest(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/memstats" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			// 100 first, then a peak, then 150 for the rest.
			heap := map[int64]int{1: 100, 2: 900}[n.Add(1)]
			if heap == 0 {
				heap = 150
			}
			fmt.Fprintf(w, `{"heap_alloc":%d,"sys":5000}`, heap)
		})
		res, err := Load(context.Background(), NewLoadClient(testTimeout, 4), options(adminURL))
		if err != nil {
			t.Fatal(err)
		}
		if res.HeapStart != 100 || res.HeapPeak != 900 || res.HeapEnd != 150 {
			t.Errorf("heap start %d, peak %d, end %d; want 100, 900, 150", res.HeapStart, res.HeapPeak, res.HeapEnd)
		}
	})
	t.Run("a failing endpoint is not fatal", func(t *testing.T) {
		t.Parallel()
		var n atomic.Int64
		adminURL := serveTest(t, func(w http.ResponseWriter, r *http.Request) {
			switch n.Add(1) % 4 {
			case 0:
				w.WriteHeader(http.StatusInternalServerError)
			case 1:
				fmt.Fprint(w, `not JSON`)
			case 2:
				fmt.Fprint(w, `{"heap_alloc":0}`)
			case 3:
				http.Redirect(w, r, "http://192.0.2.1/memstats", http.StatusFound)
			}
		})
		res, err := Load(context.Background(), NewLoadClient(testTimeout, 4), options(adminURL))
		if err != nil {
			t.Fatal(err)
		}
		if res.MemPolls < 2 || res.MemPollFailures != res.MemPolls {
			t.Errorf("%d polls, %d failed; want every poll counted as failed", res.MemPolls, res.MemPollFailures)
		}
		if res.HeapStart != 0 || res.HeapPeak != 0 || res.HeapEnd != 0 || res.Sent == 0 {
			t.Errorf("heap %d, %d, %d and %d sent; want no heap figure and the run to go on",
				res.HeapStart, res.HeapPeak, res.HeapEnd, res.Sent)
		}
	})
	t.Run("without an admin URL", func(t *testing.T) {
		t.Parallel()
		res, err := Load(context.Background(), NewLoadClient(testTimeout, 4), options(nil))
		if err != nil {
			t.Fatal(err)
		}
		if res.MemAsked || res.MemPolls != 0 || res.MemPollFailures != 0 || res.HeapStart != 0 || res.HeapPeak != 0 || res.HeapEnd != 0 {
			t.Errorf("memory figures without an admin URL: %+v", res)
		}
	})
}

// TestLoadResultDoesNotGrow: what a run keeps is the same size however many
// requests it sends.
func TestLoadResultDoesNotGrow(t *testing.T) {
	t.Parallel()
	one, many := newLoadStats(), newLoadStats()
	record := func(s *loadStats, n int) {
		for i := range n {
			s.record(200+i%3, time.Duration(i%5000)*time.Microsecond, nil, i%10 == 0, false)
		}
	}
	record(one, 1)
	record(many, 2_000_000)
	many.starting(3 * time.Millisecond)
	many.starting(time.Millisecond)
	var res LoadResult
	many.into(&res)
	if res.MaxLagUS != 3000 || res.Sent != 2_000_000 {
		t.Errorf("result = %d us latest start and %d sent, want 3000 and 2000000", res.MaxLagUS, res.Sent)
	}
	if len(many.byStatus) != 3 || many.sent != 2_000_000 || many.attacks != 200_000 {
		t.Errorf("stats = %d statuses, %d sent, %d attacks", len(many.byStatus), many.sent, many.attacks)
	}
	if len(one.hist.counts) != len(many.hist.counts) || len(many.hist.counts) != histBuckets {
		t.Errorf("the histogram has %d buckets after 2 000 000 values and %d after one", len(many.hist.counts), len(one.hist.counts))
	}
}

func TestLoadAgainstTarget(t *testing.T) {
	t.Parallel()
	var access, decisions bytes.Buffer
	handler, err := target.Handler(target.Config{
		Mode: aegolith.ModeEnforce, Access: records.NewWriter(&access), Decisions: records.NewWriter(&decisions),
	})
	if err != nil {
		t.Fatal(err)
	}
	base := serveTest(t, handler.ServeHTTP)
	cs := []cases.Case{
		{ID: "a", Expected: cases.Attack, Method: "GET", Path: "/x", RawQuery: "q=1%27%20OR%20%271%27%3D%271"},
		{ID: "l", Expected: cases.Legit, Method: "GET", Path: "/x", RawQuery: "q=apples"},
	}
	res, err := Load(context.Background(), NewLoadClient(testTimeout, 8), LoadOptions{
		Base: base, Cases: cs, RPS: 400, Workers: 8, Duration: 250 * time.Millisecond, AttackShare: 0.3, Seed: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Attacks == 0 || res.ByStatus[http.StatusForbidden] != res.Attacks ||
		res.ByStatus[http.StatusOK] != res.Sent-res.Attacks {
		t.Errorf("by status = %v with %d attacks of %d sent", res.ByStatus, res.Attacks, res.Sent)
	}
	// Records of a detection run in the same log are not this run's.
	decisions.WriteString(`{"id":"b0000000-` + strings.Repeat("a", 64) + `","action":"block","rules":["X"],"latency_us":999999999}` + "\n")
	lat, err := ReadDecisionLatency(&decisions, res.IDPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if lat.Records != res.Attacks || lat.Requests != res.Attacks || lat.Skipped != 0 || lat.Other != 1 || lat.Unreadable != 0 {
		t.Errorf("decision latency over %d records (%d skipped, %d other), want the %d blocked attacks and 1 other",
			lat.Records, lat.Skipped, lat.Other, res.Attacks)
	}
	if lat.P50US <= 0 || lat.P50US > lat.P99US || lat.P99US > lat.MaxUS || lat.MaxUS >= 999999999 {
		t.Errorf("decision latency %d, %d, max %d", lat.P50US, lat.P99US, lat.MaxUS)
	}
	// The firewall's own time is part of the round trip.
	if lat.P50US > res.MaxUS {
		t.Errorf("a decision took %d us, the longest round trip %d us", lat.P50US, res.MaxUS)
	}
}

func TestReadDecisionLatency(t *testing.T) {
	t.Parallel()
	var log strings.Builder
	for i := 1; i <= 100; i++ {
		fmt.Fprintf(&log, `{"id":"load-x-%d","action":"block","rules":["R"],"latency_us":%d}`+"\n", i, i)
	}
	log.WriteString(`{"id":"load-x-200","action":"allow","monitored":true,"rules":["R"],"latency_us":200}` + "\n")
	// A second record of one request counts too.
	log.WriteString(`{"id":"load-x-200","action":"allow","monitored":true,"rules":["R"],"latency_us":250}` + "\n")
	// A request the firewall failed to inspect has no latency.
	log.WriteString(`{"id":"load-x-300","action":"block","rules":[],"latency_us":0,"error":"inspection failed"}` + "\n")
	log.WriteString(`{"id":"load-x-301","action":"block","rules":[],"latency_us":0,"error":"inspection failed"}` + "\n")
	// Another error keeps its latency.
	log.WriteString(`{"id":"load-x-302","action":"allow","rules":[],"latency_us":300,"error":"budget"}` + "\n")
	log.WriteString(`{"id":"load-y-1","action":"block","rules":["R"],"latency_us":5000000}` + "\n")
	log.WriteString(`{"id":"load-x-303","action":"bl` + "\n\n")

	lat, err := ReadDecisionLatency(strings.NewReader(log.String()), "load-x-")
	if err != nil {
		t.Fatal(err)
	}
	want := DecisionLatency{Records: 103, Requests: 102, Skipped: 2, Other: 1, Unreadable: 1, P50US: 52, P90US: 93, P99US: 250, MaxUS: 300}
	if lat != want {
		t.Errorf("decision latency = %+v, want %+v", lat, want)
	}
	empty, err := ReadDecisionLatency(strings.NewReader(""), "load-x-")
	if err != nil || empty != (DecisionLatency{}) {
		t.Errorf("an empty log gives %+v, %v", empty, err)
	}
	if _, err := ReadDecisionLatency(failingReader{}, "load-x-"); err == nil {
		t.Error("a log that cannot be read is no error")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, fmt.Errorf("broken") }
