package run

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"syscall"

	"github.com/ergasterion-dev/aegolith/bench/internal/records"
)

// Outcome is what happened to one case.
type Outcome string

// The values of Outcome.
const (
	// Blocked: the firewall blocked the request.
	Blocked Outcome = "blocked"
	// Flagged: the request was allowed, and a rule other than a route rule
	// matched in monitor.
	Flagged Outcome = "flagged"
	// RouteOnly: the request was allowed, and only route rules matched.
	RouteOnly Outcome = "route-only"
	// Passed: the request reached the target and nothing was decided about it.
	Passed Outcome = "passed"
	// Rejected: the server answered before the firewall saw the request.
	Rejected Outcome = "rejected"
	// Unknown: the answer and the logs do not say what happened.
	Unknown Outcome = "unknown"
	// NotSent: the case was not sent.
	NotSent Outcome = "not-sent"
)

// Result is one line of a results file.
type Result struct {
	CaseID    string   `json:"case_id"`
	RequestID string   `json:"request_id"`
	Status    int      `json:"status"` // 0 when no answer arrived
	Outcome   Outcome  `json:"outcome"`
	Rules     []string `json:"rules,omitempty"` // rule IDs of the decisions, sorted
	// LatencyUS is the time the client waited for the answer, not the time
	// the firewall took.
	LatencyUS int64  `json:"latency_us"`
	Reason    string `json:"reason,omitempty"` // never repeats a request value
}

const (
	routeRulePrefix = "AEG-ROUTE-"
	actionBlock     = "block"
)

// rejections are the statuses net/http answers with before any handler runs.
var rejections = []int{
	http.StatusBadRequest,
	http.StatusRequestURITooLong,
	http.StatusExpectationFailed,
	http.StatusRequestHeaderFieldsTooLarge,
	http.StatusNotImplemented,
}

// Classify judges one case from the status of its answer (0 for none), the
// error of sending it, its access record (nil for none) and its decision
// records. The second value says why, where the outcome does not say it all.
//
// A request without an access record never counts as passed: it was either
// rejected before the firewall or its fate is unknown. Nor does a request the
// firewall failed to inspect.
func Classify(status int, sendErr error, access *records.Access, ds []records.Decision) (Outcome, string) {
	if sendErr != nil && status == 0 {
		var refused *NotSentError
		if errors.As(sendErr, &refused) {
			return NotSent, refused.Reason
		}
		return Unknown, noResponse(sendErr)
	}
	if access == nil {
		if slices.Contains(rejections, status) {
			return Rejected, fmt.Sprintf("answered %d before the firewall", status)
		}
		return Unknown, fmt.Sprintf("no access record, status %d", status)
	}

	var blocked, failedBlock, flagged, routeOnly, failed bool
	for _, d := range ds {
		switch {
		case d.Action == actionBlock:
			blocked = true
			failedBlock = failedBlock || d.Error != ""
		case d.Monitored && slices.ContainsFunc(d.Rules, isContentRule):
			flagged = true
		case d.Monitored && len(d.Rules) > 0:
			routeOnly = true
		case d.Error != "" && len(d.Rules) == 0:
			failed = true
		}
	}
	switch {
	case blocked && failedBlock:
		return Blocked, "blocked with an inspection error"
	case blocked:
		return Blocked, ""
	case flagged:
		return Flagged, ""
	case routeOnly:
		return RouteOnly, ""
	case failed:
		return Unknown, "allowed after an inspection error, no rules"
	case status == http.StatusForbidden:
		return Unknown, "status 403 without a decision"
	}
	return Passed, ""
}

func isContentRule(id string) bool { return !strings.HasPrefix(id, routeRulePrefix) }

// noResponse describes a transport error in fixed words: the error's own text
// can name addresses or repeat parts of a request.
func noResponse(err error) string {
	var netErr net.Error
	what := "transport error"
	switch {
	case errors.Is(err, context.Canceled):
		what = "cancelled"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		what = "timed out"
	case errors.Is(err, syscall.ECONNREFUSED):
		what = "connection refused"
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		what = "connection reset"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		what = "connection closed"
	}
	return "no response: " + what
}

// Join returns a copy of rs with each outcome set from the access and decision
// logs, both keyed by request ID. A case that was not sent stays so. Where
// Detect gave a reason for a missing answer, it is kept.
func Join(rs []Result, access map[string]records.Access, ds map[string][]records.Decision) []Result {
	out := slices.Clone(rs)
	for i := range out {
		r := &out[i]
		if r.Outcome == NotSent {
			continue
		}
		var arrived *records.Access
		if a, ok := access[r.RequestID]; ok {
			arrived = &a
		}
		var sendErr error
		if r.Status == 0 {
			sendErr = errors.New("no response")
		}
		decisions := ds[r.RequestID]
		outcome, reason := Classify(r.Status, sendErr, arrived, decisions)
		r.Outcome = outcome
		if sendErr == nil || r.Reason == "" {
			r.Reason = reason
		}
		r.Rules = ruleIDs(decisions)
	}
	return out
}

// ruleIDs returns the distinct rule IDs of ds, sorted, nil when there are
// none.
func ruleIDs(ds []records.Decision) []string {
	var ids []string
	for _, d := range ds {
		ids = append(ids, d.Rules...)
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}
