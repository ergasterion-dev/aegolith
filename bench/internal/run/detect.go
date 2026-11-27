package run

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/ergasterion-dev/aegolith/bench/internal/cases"
)

// Detect sends every case once, one at a time and in order, and returns one
// Result per case. The request ID of a case is idPrefix followed by its ID, so
// the cases should be merged: repeats would share a request ID.
//
// rps is a ceiling on requests per second (0 or less for none); a target that
// answers more slowly is sent to more slowly.
//
// Outcome is left empty, for Join to set from the target's logs, except for a
// case that was not sent: one the client cannot send as given, or one reached
// after ctx was cancelled. A case without an answer has status 0 and a reason.
func Detect(ctx context.Context, c *http.Client, base *url.URL, cs []cases.Case, idPrefix string, rps int) []Result {
	var tick <-chan time.Time // nil without a rate ceiling
	if rps > 0 {
		if interval := time.Second / time.Duration(rps); interval > 0 {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			tick = ticker.C
		}
	}
	out := make([]Result, 0, len(cs))
	for i, one := range cs {
		if i > 0 && tick != nil {
			select {
			case <-tick:
			case <-ctx.Done():
			}
		}
		r := Result{CaseID: one.ID, RequestID: idPrefix + one.ID}
		if ctx.Err() != nil {
			r.Outcome, r.Reason = NotSent, "the run was cancelled"
		} else {
			send(ctx, c, base, one, &r)
		}
		out = append(out, r)
	}
	return out
}

// SendCase sends one case as Detect does, with requestID as its X-Request-Id,
// and returns its result: Outcome is NotSent if the client cannot send the
// case as given, and empty otherwise, for Join to set.
func SendCase(ctx context.Context, c *http.Client, base *url.URL, one cases.Case, requestID string) Result {
	r := Result{CaseID: one.ID, RequestID: requestID}
	send(ctx, c, base, one, &r)
	return r
}

// send sends one case and notes in r what came of it.
func send(ctx context.Context, c *http.Client, base *url.URL, one cases.Case, r *Result) {
	status, latency, err := Send(ctx, c, base, one, r.RequestID)
	r.Status, r.LatencyUS = status, latency.Microseconds()
	var refused *NotSentError
	switch {
	case errors.As(err, &refused):
		r.Outcome, r.Reason = NotSent, refused.Reason
	case err != nil:
		r.Reason = noResponse(err)
	}
}
