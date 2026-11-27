package remote

import (
	"errors"
	"maps"
	"slices"
	"strings"

	"github.com/ergasterion-dev/aegolith/bench/internal/records"
	"github.com/ergasterion-dev/aegolith/bench/internal/run"
)

// The parts of a control's and a health check's request ID after the run's
// prefix and tag; see Run.
const (
	controlInfix = "control-"
	healthInfix  = "health-"
)

// Coverage says how many of the requests a remote run sent the target's logs
// hold.
type Coverage struct {
	// Sent counts the case requests sent; WithAccess and WithDecision those
	// of them with an access record and with at least one decision record.
	Sent, WithAccess, WithDecision int
}

// CheckLogs checks, before rs are joined with them, that access and ds are
// the logs of the run that wrote rs, and says how many of its requests they
// hold. A run's request IDs start with the target's prefix and the run tag;
// CheckLogs reads that start from the request IDs of the cases sent.
//
// It refuses when the access log holds no control and no health check of the
// run: controls go to allow-listed routes with a harmless value, so the
// application logs them whatever the firewall decides, while a case may be
// blocked before the application sees it. It refuses when cases were sent and
// no decision record carries the run's prefix and tag, unless noDecisions says
// that the firewall truly decided nothing about the run: an empty, misnamed or
// other replica's decision log would otherwise read every case as passed.
// It refuses results of more than one run. With no case sent there is nothing
// to check. Its errors never name a case or the run.
func CheckLogs(rs []run.Result, access map[string]records.Access, ds map[string][]records.Decision, noDecisions bool) (Coverage, error) {
	var cov Coverage
	prefix := ""
	for _, r := range rs {
		if r.Outcome == run.NotSent {
			continue
		}
		p, ok := strings.CutSuffix(r.RequestID, r.CaseID)
		if r.RequestID == "" || !ok || !strings.HasSuffix(p, "-") || p == "-" {
			return Coverage{}, errors.New("a sent result's request ID is not a remote run's prefix, tag and case ID")
		}
		if prefix != "" && p != prefix {
			return Coverage{}, errors.New("the results hold requests of more than one run; join each run's results with its own logs")
		}
		prefix = p
		cov.Sent++
		if _, ok := access[r.RequestID]; ok {
			cov.WithAccess++
		}
		if len(ds[r.RequestID]) > 0 {
			cov.WithDecision++
		}
	}
	if cov.Sent == 0 {
		return cov, nil
	}
	ofRun := func(infixes ...string) func(string) bool {
		return func(id string) bool {
			return slices.ContainsFunc(infixes, func(infix string) bool { return strings.HasPrefix(id, prefix+infix) })
		}
	}
	if !slices.ContainsFunc(slices.Collect(maps.Keys(access)), ofRun(controlInfix, healthInfix)) {
		return Coverage{}, errors.New("the access log holds no control request and no health check of this run: " +
			"it is empty, of another run or of another replica, or the application does not log them")
	}
	if !noDecisions && !slices.ContainsFunc(slices.Collect(maps.Keys(ds)), ofRun("")) {
		return Coverage{}, errors.New("the decision log holds no record of this run, so every case would read as passed: " +
			"it is empty, of another run or of another replica; give --allow-no-decisions only if the firewall " +
			"truly decided nothing about the run")
	}
	return cov, nil
}
