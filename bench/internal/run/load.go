package run

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
	"github.com/ergasterion-dev/aegolith/bench/internal/records"
)

// Limits and intervals of the load phase.
const (
	// MaxLoadRPS is the highest rate Load takes. It keeps the arithmetic of
	// the schedule within an int64.
	MaxLoadRPS = 1_000_000
	// MaxLoadWorkers is the most requests Load keeps in flight.
	MaxLoadWorkers = 1 << 16
	// memPollInterval is how often the target's memory is read during a run.
	memPollInterval = 5 * time.Second
	// memPollTimeout bounds one reading of the target's memory.
	memPollTimeout = 2 * time.Second
	// lastPollTimeout bounds the last reading of an interrupted run, which
	// has to return soon.
	lastPollTimeout = 500 * time.Millisecond
)

// inspectionFailed is the error of the decision record the target writes for a
// request it blocked because inspecting it panicked. Such a record has no
// latency.
const inspectionFailed = "inspection failed"

// LoadOptions says what Load sends.
type LoadOptions struct {
	// Base is the scheme and host of the target. AdminURL, if set, is the
	// scheme and host that serve the target's GET /memstats.
	Base, AdminURL *url.URL
	// Cases is where requests are drawn from: attack and legitimate cases
	// only. A near-miss case is never used.
	Cases []cases.Case
	// RPS is the number of requests scheduled per second. Workers is how many
	// may be in flight at once.
	RPS, Workers int
	Duration     time.Duration
	// AttackShare is the share of requests drawn from the attack cases, from 0
	// to 1. The rest are drawn from the legitimate cases.
	AttackShare float64
	// Seed decides which case each place of the schedule gets.
	Seed int64

	// memInterval replaces memPollInterval in tests.
	memInterval time.Duration
}

// LoadResultFormat is the version of LoadResult as a file. It changes whenever
// a field is added or changes its meaning: a field missing from an older file
// would read as zero and be reported as measured.
const LoadResultFormat = 2

// LoadResult is what one load run measured. Its size does not depend on how
// long the run was. It names no case and holds no per-case outcome.
type LoadResult struct {
	// Format is LoadResultFormat. A result with another value was written by
	// another version of this program and must not be read as this struct.
	Format int

	// What was asked for.
	RPS, Workers int
	AttackShare  float64
	Seed         int64
	// AttackCases and LegitCases are the sizes of the two sets requests were
	// drawn from. Excluded counts the attack and legitimate cases left out of
	// them before the run because the client cannot send them as given.
	AttackCases, LegitCases, Excluded int
	// Conflicting is for the caller that merged the cases: how many it left
	// out because their sources disagree on what to expect. Load leaves it 0.
	Conflicting int
	// IDPrefix starts the X-Request-Id of every request of this run.
	IDPrefix string

	// Sent counts the requests that were sent and came to an end: an answer or
	// a transport error. Attacks of them were drawn from the attack cases.
	Sent, TransportErrors, Attacks int
	// Dropped counts the places of the schedule that found every worker busy.
	// Nothing was sent for them, so they have no latency.
	Dropped int
	// NotSent counts requests the client refused although their case had
	// passed the check before the run. It should be 0.
	NotSent int `json:",omitempty"`
	// Interrupted says that the run was cancelled before its end; Cancelled
	// counts the requests that were in flight then. They are in no other
	// count.
	Interrupted bool `json:",omitempty"`
	Cancelled   int  `json:",omitempty"`
	// ByStatus counts the answers by status code.
	ByStatus map[int]int

	// The client's round trip of the answered requests, in microseconds: from
	// just before a request is written until its answer has been read. It
	// holds the HTTP stacks of both sides and the connection, so it is not
	// the firewall's decision latency. The percentiles are at most 1/128
	// above the true ones (see histogram); MaxUS is exact.
	P50US, P90US, P99US, MaxUS int64
	// MaxLagUS is the longest a request was sent after its scheduled time,
	// taken by its worker just before sending. It measures the generator, not
	// the target.
	MaxLagUS int64

	// The target's heap in bytes (runtime.MemStats.HeapAlloc, which includes
	// garbage not yet collected): at the first reading, the highest reading
	// and the last. 0 means that reading failed or none was made.
	HeapStart, HeapPeak, HeapEnd uint64
	// MemAsked says that an admin URL was given. MemPolls counts the readings
	// of the target's memory that came to an end, MemPollFailures those of
	// them that failed. A reading still in progress when the schedule ends or
	// the run is interrupted is abandoned and not counted, whether it would
	// have succeeded or failed; the last reading, made after that, is counted.
	MemAsked                  bool `json:",omitempty"`
	MemPolls, MemPollFailures int

	// Duration is how long the schedule ran: the time asked for, or the time
	// until the run was cancelled. AchievedRPS is Sent over Duration.
	Duration    time.Duration
	AchievedRPS float64

	// Decisions is the firewall's own latency, when the caller read it from
	// the target's decision log.
	Decisions *DecisionLatency `json:",omitempty"`
}

// NewLoadClient returns the client of a load run: NewClient, keeping one idle
// connection per worker, so that connections are reused however many workers
// there are.
func NewLoadClient(timeout time.Duration, workers int) *http.Client {
	c := NewClient(timeout)
	if t, ok := c.Transport.(*http.Transport); ok && workers > t.MaxIdleConnsPerHost {
		t.MaxIdleConnsPerHost = workers
	}
	return c
}

// Load sends requests to the target for o.Duration and returns what it
// measured. c should come from NewLoadClient.
//
// The schedule is open loop: o.RPS places per second at fixed times, whatever
// the target does. Each place gets a case drawn with o.Seed, an attack with
// probability o.AttackShare. A place whose time has come is sent at once by a
// free worker; if all o.Workers are busy it is dropped and counted, never
// queued. So a slow target shows as dropped places and a lower AchievedRPS,
// while the latency of what was sent stays that of a request sent on time: it
// is measured from the moment of sending and never includes time spent
// waiting for a worker, because nothing waits.
//
// Whether a connection is reused is up to the client, not to a case: a
// Connection header of a case is not sent. (The sender itself still closes
// the connection after a case with a Transfer-Encoding other than "chunked".)
// Cases the client cannot send as given are left out before the run and
// counted in Excluded.
//
// Every request ID is IDPrefix followed by the number of its place. It is
// shorter than a case ID, so it can never be the request ID of a detection
// run, whatever prefix that run uses.
//
// With o.AdminURL set, the target's memory is read before the first request,
// every five seconds and after the last answer. A failed reading is counted.
//
// An error means that nothing was sent: the options are unusable, or a set of
// cases that o.AttackShare needs is empty. When ctx is cancelled, the requests
// in flight are abandoned and the result so far is returned, marked as
// interrupted, with a nil error.
func Load(ctx context.Context, c *http.Client, o LoadOptions) (LoadResult, error) {
	total, err := checkLoad(o)
	if err != nil {
		return LoadResult{}, err
	}
	pools, err := newLoadPools(o)
	if err != nil {
		return LoadResult{}, err
	}
	res := LoadResult{
		Format: LoadResultFormat,
		RPS:    o.RPS, Workers: o.Workers, AttackShare: o.AttackShare, Seed: o.Seed,
		AttackCases: len(pools.attack), LegitCases: len(pools.legit), Excluded: pools.excluded,
	}

	var mem *memPoller
	if o.AdminURL != nil {
		res.MemAsked = true
		mem = &memPoller{c: c, url: (&url.URL{Scheme: o.AdminURL.Scheme, Host: o.AdminURL.Host, Path: "/memstats"}).String()}
		res.HeapStart = mem.poll(ctx, memPollTimeout)
	}
	pollCtx, stopPolls := context.WithCancel(ctx)
	defer stopPolls()
	polled := make(chan struct{})
	if mem != nil {
		go mem.run(pollCtx, o.memInterval, polled)
	} else {
		close(polled)
	}

	start := time.Now()
	idPrefix := loadIDPrefix(start)
	res.IDPrefix = idPrefix
	stats := newLoadStats()
	pick := newPicker(pools, o.AttackShare, o.Seed)
	free := make(chan struct{}, o.Workers)
	var inFlight sync.WaitGroup
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	// until waits for a time of the schedule; false means ctx was cancelled.
	until := func(at time.Time) bool {
		if d := time.Until(at); d > 0 {
			timer.Reset(d)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return false
			}
		}
		return ctx.Err() == nil
	}

	finished := true
schedule:
	for place := range total {
		at := start.Add(placeOffset(place, int64(o.RPS)))
		if !until(at) {
			finished = false
			break
		}
		// Drawn for a dropped place too: which case a place gets must not
		// depend on how fast the target is.
		one, attack := pick.next()
		select {
		case free <- struct{}{}:
		default:
			res.Dropped++
			continue
		}
		// A worker that became free because the run was cancelled sends
		// nothing more.
		if ctx.Err() != nil {
			<-free
			finished = false
			break schedule
		}
		inFlight.Add(1)
		go func() {
			defer inFlight.Done()
			defer func() { <-free }()
			stats.starting(time.Since(at))
			status, latency, err := Send(ctx, c, o.Base, one, idPrefix+strconv.FormatInt(place, 10))
			stats.record(status, latency, err, attack, ctx.Err() != nil)
		}()
	}
	if finished {
		// The last place is one interval before the end.
		until(start.Add(o.Duration))
	}
	res.Duration = time.Since(start)
	// Bounded by the client's timeout, and by nothing once ctx is cancelled.
	inFlight.Wait()
	stopPolls()
	<-polled
	if mem != nil {
		timeout := memPollTimeout
		if ctx.Err() != nil {
			timeout = lastPollTimeout
		}
		res.HeapEnd = mem.poll(context.WithoutCancel(ctx), timeout)
		res.HeapPeak, res.MemPolls, res.MemPollFailures = mem.peak, mem.polls, mem.failures
	}

	res.Interrupted = ctx.Err() != nil
	stats.into(&res)
	if seconds := res.Duration.Seconds(); seconds > 0 {
		res.AchievedRPS = float64(res.Sent) / seconds
	}
	return res, nil
}

// checkLoad checks the options but the cases and returns how many places the
// schedule has.
func checkLoad(o LoadOptions) (total int64, err error) {
	switch {
	case !usableBase(o.Base):
		return 0, errors.New("load: the base URL is not http or https with a host")
	case o.AdminURL != nil && !usableBase(o.AdminURL):
		return 0, errors.New("load: the admin URL is not http or https with a host")
	case o.RPS < 1 || o.RPS > MaxLoadRPS:
		return 0, fmt.Errorf("load: the rate must be 1 to %d requests per second", MaxLoadRPS)
	case o.Workers < 1 || o.Workers > MaxLoadWorkers:
		return 0, fmt.Errorf("load: the number of workers must be 1 to %d", MaxLoadWorkers)
	case o.Duration <= 0:
		return 0, errors.New("load: the duration must be above zero")
	case !(o.AttackShare >= 0 && o.AttackShare <= 1): // also refuses NaN
		return 0, errors.New("load: the attack share must be from 0 to 1")
	}
	rps := int64(o.RPS)
	total = int64(o.Duration/time.Second)*rps + int64(o.Duration%time.Second)*rps/int64(time.Second)
	if total < 1 {
		return 0, errors.New("load: the duration is shorter than one request at this rate")
	}
	return total, nil
}

func usableBase(u *url.URL) bool {
	return u != nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// placeOffset is when place i of the schedule is due, counted from the start.
// It does not drift: the whole seconds are exact.
func placeOffset(i, rps int64) time.Duration {
	return time.Duration(i/rps)*time.Second + time.Duration(i%rps)*time.Second/time.Duration(rps)
}

// loadIDPrefix returns the start of the request IDs of a run that begins at
// start: at most 19 characters, which with the number of a place stays under
// the 64 of a case ID.
func loadIDPrefix(start time.Time) string {
	return "load-" + strconv.FormatUint(uint64(start.UnixNano()), 36) + "-"
}

// loadPools are the cases a run draws from, in the order they were given.
type loadPools struct {
	attack, legit []cases.Case
	excluded      int
}

// newLoadPools sorts the cases of o into the two sets, without the Connection
// header and without the cases that cannot be sent. It fails if a set that
// o.AttackShare needs is empty.
func newLoadPools(o LoadOptions) (loadPools, error) {
	var p loadPools
	for _, c := range o.Cases {
		if c.Expected != cases.Attack && c.Expected != cases.Legit {
			continue
		}
		c = withoutConnection(c)
		// Whether a case can be sent does not depend on the request ID.
		if _, err := newRequest(context.Background(), o.Base, c, "load-0"); err != nil {
			p.excluded++
			continue
		}
		if c.Expected == cases.Attack {
			p.attack = append(p.attack, c)
		} else {
			p.legit = append(p.legit, c)
		}
	}
	switch {
	case o.AttackShare > 0 && len(p.attack) == 0:
		return p, fmt.Errorf("load: the attack share is above 0 and no attack case can be sent (%d cases left out as unsendable)", p.excluded)
	case o.AttackShare < 1 && len(p.legit) == 0:
		return p, fmt.Errorf("load: the attack share is below 1 and no legitimate case can be sent (%d cases left out as unsendable)", p.excluded)
	}
	return p, nil
}

// withoutConnection returns c without a Connection header. The headers of c
// itself are left alone.
func withoutConnection(c cases.Case) cases.Case {
	for name := range c.Headers {
		if !strings.EqualFold(name, "Connection") {
			continue
		}
		headers := make(map[string]string, len(c.Headers))
		for n, v := range c.Headers {
			if !strings.EqualFold(n, "Connection") {
				headers[n] = v
			}
		}
		c.Headers = headers
		break
	}
	return c
}

// picker draws the case of each place of the schedule.
type picker struct {
	pools loadPools
	share float64
	rng   *rand.Rand
}

func newPicker(pools loadPools, share float64, seed int64) *picker {
	return &picker{pools: pools, share: share, rng: rand.New(rand.NewPCG(uint64(seed), 0x6c6f6164))}
}

// next returns the case of the next place and whether it is an attack. The
// set it needs is not empty, see newLoadPools.
func (p *picker) next() (c cases.Case, attack bool) {
	// Float64 is below 1, so a share of 1 always draws an attack and a share
	// of 0 never does.
	if p.rng.Float64() < p.share {
		return p.pools.attack[p.rng.IntN(len(p.pools.attack))], true
	}
	return p.pools.legit[p.rng.IntN(len(p.pools.legit))], false
}

// loadStats is what the workers count. It keeps a count per status code and a
// histogram of fixed size, and nothing per request.
type loadStats struct {
	mu                                       sync.Mutex
	sent, errors, attacks, notSent, canceled int
	lagUS                                    int64
	byStatus                                 map[int]int
	hist                                     histogram
}

func newLoadStats() *loadStats { return &loadStats{byStatus: map[int]int{}} }

// starting notes how long after its scheduled time a request is sent.
func (s *loadStats) starting(lag time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lagUS = max(s.lagUS, lag.Microseconds())
}

// record counts the end of one request. cancelled says that the run had been
// cancelled by then, which is taken as the cause of an error.
func (s *loadStats) record(status int, latency time.Duration, err error, attack, cancelled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var refused *NotSentError
	switch {
	case errors.As(err, &refused):
		s.notSent++
		return
	case err != nil && cancelled:
		s.canceled++
		return
	case err != nil:
		s.errors++
	default:
		s.byStatus[status]++
		s.hist.add(latency.Microseconds())
	}
	s.sent++
	if attack {
		s.attacks++
	}
}

// into copies the counts into res, once no worker is left.
func (s *loadStats) into(res *LoadResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res.Sent, res.TransportErrors, res.Attacks = s.sent, s.errors, s.attacks
	res.NotSent, res.Cancelled = s.notSent, s.canceled
	res.ByStatus = s.byStatus
	res.P50US, res.P90US, res.P99US = s.hist.percentile(50), s.hist.percentile(90), s.hist.percentile(99)
	res.MaxUS, res.MaxLagUS = s.hist.max, s.lagUS
}

// memPoller reads the target's heap. It is used by one goroutine at a time.
type memPoller struct {
	c               *http.Client
	url             string
	peak            uint64
	polls, failures int
}

// run polls every interval until ctx is cancelled, then closes done.
func (m *memPoller) run(ctx context.Context, interval time.Duration, done chan<- struct{}) {
	defer close(done)
	if interval <= 0 {
		interval = memPollInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.poll(ctx, memPollTimeout)
		}
	}
}

// poll reads the heap once and returns it, or 0 if that failed. A reading
// that ctx cut short is not counted at all.
func (m *memPoller) poll(ctx context.Context, timeout time.Duration) uint64 {
	limited, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	heap, err := m.read(limited)
	if err != nil && ctx.Err() != nil {
		return 0
	}
	m.polls++
	if err != nil {
		m.failures++
		return 0
	}
	m.peak = max(m.peak, heap)
	return heap
}

func (m *memPoller) read(ctx context.Context) (uint64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := m.c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, errors.New("the status is not 200")
	}
	var stats struct {
		HeapAlloc uint64 `json:"heap_alloc"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&stats); err != nil {
		return 0, err
	}
	if stats.HeapAlloc == 0 {
		// The heap of a running Go program is never empty.
		return 0, errors.New("no heap size in the answer")
	}
	return stats.HeapAlloc, nil
}

// DecisionLatency is the firewall's own time per request, as its decision log
// records it, for the requests of one load run. The firewall leaves a record
// only for a request it blocked, matched a rule on in monitor mode or failed
// on: a request it passed has none, so this is not the latency of all
// requests.
type DecisionLatency struct {
	// Records is the number of decision records the figures are over,
	// Requests the number of requests they belong to.
	Records, Requests int
	// Skipped counts the records of requests blocked because inspecting them
	// failed: they carry no latency.
	Skipped int
	// Other counts the records of other runs in the same log, Unreadable the
	// lines that are no decision record.
	Other, Unreadable int
	// Microseconds, with the error of LoadResult's percentiles.
	P50US, P90US, P99US, MaxUS int64
}

// ReadDecisionLatency reads a decision log and returns the decision latency of
// the records whose request ID starts with idPrefix, the IDPrefix of a load
// run. The error is non-nil only if r fails.
func ReadDecisionLatency(r io.Reader, idPrefix string) (DecisionLatency, error) {
	decisions, unreadable, err := records.ReadDecisions(r)
	if err != nil {
		return DecisionLatency{}, err
	}
	out := DecisionLatency{Unreadable: unreadable}
	var hist histogram
	for id, ds := range decisions {
		timed := false
		for _, d := range ds {
			switch {
			case !strings.HasPrefix(id, idPrefix):
				out.Other++
			case d.Error == inspectionFailed:
				out.Skipped++
			default:
				out.Records++
				timed = true
				hist.add(d.LatencyUS)
			}
		}
		if timed {
			out.Requests++
		}
	}
	out.P50US, out.P90US, out.P99US = hist.percentile(50), hist.percentile(90), hist.percentile(99)
	out.MaxUS = hist.max
	return out, nil
}
