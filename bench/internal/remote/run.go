package remote

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
	"github.com/ergasterion-dev/aegolith/bench/internal/run"
)

const (
	// ControlValue is the harmless value a control request puts into every
	// placement of its entry.
	ControlValue = "aegobench-control"
	// runTagLen is the length of the random tag of a run's request IDs.
	runTagLen = 8
	// waitSlice bounds how long a wait for the next request goes without
	// checking the stop file and the heartbeat.
	waitSlice = 250 * time.Millisecond
	// ReasonNotJoined is the reason of a case sent until it is joined.
	ReasonNotJoined = "not yet joined with the target's logs"
	// sendTimeout is how long one request may take.
	sendTimeout = 10 * time.Second
)

// Clock is the time a run is paced and checked by.
type Clock interface {
	Now() time.Time
	// Sleep waits for d or until ctx is done, and returns ctx.Err().
	Sleep(ctx context.Context, d time.Duration) error
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func (systemClock) Sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
	return ctx.Err()
}

// NewClient returns the client remote requests are sent with: run.NewClient
// with a new connection for every request, so that net/http never sends a
// request again on its own after a connection fails. It follows no redirect
// and verifies TLS certificates.
func NewClient(timeout time.Duration) *http.Client {
	c := run.NewClient(timeout)
	if t, ok := c.Transport.(*http.Transport); ok {
		t.DisableKeepAlives = true
	}
	return c
}

// Options configure a remote run.
type Options struct {
	Target      Target
	ConfirmHost string
	RPS         int
	// Cases are the requests to send, as Prepare's Send gives them. Run
	// sends each in ID order, rebuilt from its payload and allow entry.
	Cases []cases.Case
	// Limit is the number of case requests to send at most; controls and
	// health checks do not count.
	Limit                   int
	StopFile, HeartbeatFile string
	Client                  *http.Client // nil: NewClient
	Clock                   Clock        // nil: the system clock
	// RunTag goes into every request ID, after the prefix; empty for a
	// random one. At most 8 characters of 0-9a-f.
	RunTag string
}

// Run sends o.Cases to the target under the guard and returns one result per
// case, in ID order, and why the run stopped ("" if it completed). Nothing is
// sent when the error is non-nil: o is checked first, and every case must be
// a request Place makes for the target.
//
// The first request is a health check, which is repeated whenever
// HealthInterval has passed. Then every entry of the allow-list gets a benign
// control; only if all pass are cases sent. An entry's control is sent again
// after every ControlEvery case requests to it, and each entry that had cases
// gets a closing control after the last. Every request, at most o.RPS per
// second, waits its turn checking the stop file and the heartbeat; after a
// stop no request starts. The request ID of a case is the target's prefix,
// the run tag, "-" and the case ID; controls and health checks use the
// prefix and tag with "-control-" and "-health-".
//
// A case sent is unknown until run.Join sets its outcome from the target's
// logs; ReasonNotJoined says so where no other reason was given.
// A case beyond the limit, or not reached because the run stopped, is not
// sent, with a reason.
func Run(ctx context.Context, o Options) ([]run.Result, string, error) {
	if err := o.Target.Validate(o.ConfirmHost, o.RPS); err != nil {
		return nil, "", err
	}
	if o.Limit < 1 {
		return nil, "", errors.New("the limit must be at least 1")
	}
	base, err := o.Target.Base()
	if err != nil {
		return nil, "", err
	}
	tag := o.RunTag
	if tag == "" {
		if tag, err = newRunTag(); err != nil {
			return nil, "", err
		}
	}
	if len(tag) > runTagLen || strings.Trim(tag, "0123456789abcdef") != "" || tag == "" {
		return nil, "", errors.New("the run tag must be 1 to 8 characters of 0-9a-f")
	}
	idPrefix := o.Target.RequestIDPrefix + tag + "-"

	cs := slices.Clone(o.Cases)
	slices.SortFunc(cs, func(a, b cases.Case) int { return strings.Compare(a.ID, b.ID) })
	requests := make([]cases.Case, len(cs))
	entries := make([]int, len(cs))
	for i, c := range cs {
		if i > 0 && c.ID == cs[i-1].ID {
			return nil, "", errors.New("a case is given twice")
		}
		if requests[i], entries[i], err = rebuild(c, o.Target); err != nil {
			return nil, "", fmt.Errorf("case %d of %d: %w; nothing was sent", i+1, len(cs), err)
		}
		if !run.ValidRequestID(idPrefix + c.ID) {
			return nil, "", errors.New("a request ID would not be valid")
		}
	}

	s := &sender{
		ctx: ctx, client: o.Client, clock: o.Clock, base: base, target: o.Target, idPrefix: idPrefix,
		interval: time.Second / time.Duration(o.RPS),
		guard:    &Guard{Target: o.Target, StopFile: o.StopFile, HeartbeatFile: o.HeartbeatFile},
		controls: make([]int, len(o.Target.Allow)),
	}
	if s.client == nil {
		s.client = NewClient(sendTimeout)
	}
	if s.clock == nil {
		s.clock = systemClock{}
	}

	attempt := min(len(cs), o.Limit)
	last := map[int]int{} // the last case index of each entry
	for i := range attempt {
		last[entries[i]] = i
	}
	for e := range o.Target.Allow {
		s.control(e)
	}
	results := make([]run.Result, 0, len(cs))
	sentTo := map[int]int{}
	for i := range attempt {
		c, e := cs[i], entries[i]
		if s.stop != "" {
			results = append(results, unsent(c, "the run stopped before this case: "+s.stop))
			continue
		}
		r, ok := s.send(requests[i], idPrefix+c.ID, e, kindCase)
		if !ok {
			results = append(results, unsent(c, "the run stopped before this case: "+s.stop))
			continue
		}
		r.CaseID = c.ID
		if r.Outcome == "" {
			r.Outcome = run.Unknown
			r.Reason = cmp.Or(r.Reason, ReasonNotJoined)
		}
		results = append(results, r)
		sentTo[e]++
		if sentTo[e]%ControlEvery == 0 && i != last[e] {
			s.control(e)
		}
	}
	for e := range o.Target.Allow {
		if sentTo[e] > 0 {
			s.control(e)
		}
	}
	for _, c := range cs[attempt:] {
		results = append(results, unsent(c, fmt.Sprintf("beyond the limit of %d case requests", o.Limit)))
	}
	return results, s.stop, nil
}

func unsent(c cases.Case, reason string) run.Result {
	return run.Result{CaseID: c.ID, Outcome: run.NotSent, Reason: reason}
}

func newRunTag() (string, error) {
	b := make([]byte, runTagLen/2)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("making the run tag: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// rebuild returns the request Place makes for c and the index of its entry,
// or an error if c is not one: its method and path must be an entry's, and
// one of its payloads in one of the entry's placements must give c's ID and
// request.
// What is sent is the rebuilt request, never c's own fields.
func rebuild(c cases.Case, t Target) (cases.Case, int, error) {
	i := slices.IndexFunc(t.Allow, func(e Entry) bool { return e.Method == c.Method && e.Path == c.Path })
	if i < 0 {
		return cases.Case{}, 0, errors.New("its method and path are not an allow entry")
	}
	for _, p := range t.Allow[i].placements() {
		for _, payload := range c.Payloads {
			if payloadRefusal(p.kind, payload) != "" {
				continue
			}
			built, err := request(c, t.Allow[i], p, payload)
			if err == nil && built.ID == c.ID && sameRequest(built, c) {
				return built, i, nil
			}
		}
	}
	return cases.Case{}, 0, errors.New("it is not a request Place makes for the allow-list")
}

// sameRequest reports whether a and b spell the same request.
func sameRequest(a, b cases.Case) bool {
	return a.Method == b.Method && a.Path == b.Path && a.RawQuery == b.RawQuery &&
		maps.Equal(a.Headers, b.Headers) && bytes.Equal(a.Body, b.Body)
}

// The kinds of request a run sends.
const (
	kindHealth = iota
	kindControl
	kindCase
)

// sender sends one request at a time under the guard and the rate.
type sender struct {
	ctx      context.Context
	client   *http.Client
	clock    Clock
	base     *url.URL
	target   Target
	idPrefix string
	interval time.Duration
	guard    *Guard
	next     time.Time // when the next request may start
	stop     string    // why the run stopped, "" while it runs
	health   int       // health checks sent
	controls []int     // controls sent, by entry
}

// control sends the benign control of entry e.
func (s *sender) control(e int) {
	s.controls[e]++
	id := fmt.Sprintf("%scontrol-%d-%d", s.idPrefix, e+1, s.controls[e])
	s.send(controlRequest(s.target.Allow[e]), id, e, kindControl)
}

// controlRequest puts ControlValue into every placement of e at once.
func controlRequest(e Entry) cases.Case {
	values := map[placement]string{}
	for _, p := range e.placements() {
		values[p] = ControlValue
	}
	l := cases.Line{Name: "control", Category: "control", Method: e.Method, Path: e.Path,
		Headers: map[string]string{}, Source: "control", SourceCaseID: "control", Expected: cases.Legit}
	// Neither can fail for a valid entry; an empty request would then fail
	// its control.
	_ = fill(&l, values)
	c, _ := cases.FromLine(l)
	return c
}

// send sends req as request id to entry e and judges the answer. ok is false
// if the run stopped before req was sent. A health check goes first when one
// is due.
func (s *sender) send(req cases.Case, id string, e int, kind int) (r run.Result, ok bool) {
	if s.stop != "" {
		return r, false
	}
	if kind != kindHealth && s.guard.HealthDue(s.clock.Now()) {
		s.health++
		health := cases.Case{Method: http.MethodGet, Path: s.target.HealthPath}
		s.send(health, s.idPrefix+"health-"+strconv.Itoa(s.health), e, kindHealth)
		if s.stop != "" {
			return r, false
		}
	}
	if !s.wait() {
		return r, false
	}
	start := s.clock.Now()
	s.next = start.Add(s.interval)
	headers := make(map[string]string, len(req.Headers)+len(s.target.Headers))
	for name, value := range s.target.Headers {
		headers[name] = value
	}
	for name, value := range req.Headers {
		headers[name] = value
	}
	req.Headers = headers
	r = run.SendCase(s.ctx, s.client, s.base, req, id)

	var stop bool
	var reason string
	switch {
	case s.ctx.Err() != nil:
		stop, reason = true, "the run was interrupted"
	case r.Outcome == run.NotSent:
		stop, reason = true, "a request could not be sent as built"
	case kind == kindHealth:
		stop, reason = s.guard.Health(start, r.Status)
	default:
		stop, reason = s.guard.Check(r.Status, kind == kindControl, s.target.Allow[e])
	}
	if stop {
		s.stop = reason
	}
	return r, true
}

// wait waits until the next request may start, checking the context, the
// stop file and the heartbeat before it returns and at least every
// waitSlice. It returns false, with the run stopped, if one of them says
// stop.
func (s *sender) wait() bool {
	for {
		now := s.clock.Now()
		if s.ctx.Err() != nil {
			s.stop = "the run was interrupted"
			return false
		}
		if stop, reason := s.guard.External(now); stop {
			s.stop = reason
			return false
		}
		if !now.Before(s.next) {
			return true
		}
		_ = s.clock.Sleep(s.ctx, min(s.next.Sub(now), waitSlice))
	}
}
