package remote

import (
	"strings"
	"testing"

	"github.com/ergasterion-dev/aegolith/bench/internal/records"
	"github.com/ergasterion-dev/aegolith/bench/internal/run"
)

func TestCheckLogs(t *testing.T) {
	t.Parallel()
	const run1 = "bench-0a1b2c3d-"
	sent := []run.Result{
		{CaseID: "aaa", RequestID: run1 + "aaa", Status: 200, Outcome: run.Unknown, Reason: ReasonNotJoined},
		{CaseID: "bbb", RequestID: run1 + "bbb", Status: 403, Outcome: run.Unknown, Reason: ReasonNotJoined},
		{CaseID: "ccc", RequestID: run1 + "ccc", Outcome: run.Unknown, Reason: "no response: timed out"},
		{CaseID: "ddd", Outcome: run.NotSent, Reason: "beyond the limit of 3 case requests"},
	}
	access := func(ids ...string) map[string]records.Access {
		m := map[string]records.Access{}
		for _, id := range ids {
			m[id] = records.Access{ID: id, Method: "GET", Path: "/search"}
		}
		return m
	}
	decisions := func(ids ...string) map[string][]records.Decision {
		m := map[string][]records.Decision{}
		for _, id := range ids {
			m[id] = append(m[id], records.Decision{ID: id, Action: "block", Rules: []string{"AEG-SQLI-001"}})
		}
		return m
	}
	goodAccess := access(run1+"control-1-1", run1+"aaa", run1+"bbb")
	goodDecisions := decisions(run1 + "bbb")

	cov, err := CheckLogs(sent, goodAccess, goodDecisions, false)
	if err != nil {
		t.Fatal(err)
	}
	if cov.Sent != 3 || cov.WithAccess != 2 || cov.WithDecision != 1 {
		t.Errorf("coverage %+v, want 3 sent, 2 with an access record, 1 with a decision record", cov)
	}
	// A health check of the run in the access log is enough, too.
	if _, err := CheckLogs(sent, access(run1+"health-1"), goodDecisions, false); err != nil {
		t.Errorf("health check in the access log: %v", err)
	}

	otherRun := "bench-99999999-"
	tests := map[string]struct {
		rs          []run.Result
		access      map[string]records.Access
		decisions   map[string][]records.Decision
		noDecisions bool
		want        string
	}{
		"empty decision log":        {sent, goodAccess, nil, false, "--allow-no-decisions"},
		"decision log of other run": {sent, goodAccess, decisions(otherRun + "bbb"), false, "--allow-no-decisions"},
		"decisions of other prefix": {sent, goodAccess, decisions("other-0a1b2c3d-bbb"), false, "--allow-no-decisions"},
		"empty access log":          {sent, nil, goodDecisions, false, "access log"},
		"empty access log, flag":    {sent, nil, goodDecisions, true, "access log"},
		"access log of other run":   {sent, access(otherRun + "control-1-1"), goodDecisions, false, "access log"},
		// The cases' own records do not show the log is of this run's
		// target: a control or health check must be in it.
		"access log of cases only": {sent, access(run1+"aaa", run1+"bbb"), goodDecisions, false, "control"},
		"two runs in the results": {append(sent[:1:1], run.Result{CaseID: "eee", RequestID: otherRun + "eee", Status: 200,
			Outcome: run.Unknown}), goodAccess, goodDecisions, false, "more than one run"},
		"request ID without the case ID": {[]run.Result{{CaseID: "aaa", RequestID: "bench-x", Status: 200, Outcome: run.Unknown}},
			goodAccess, goodDecisions, false, "request ID"},
		"no request ID": {[]run.Result{{CaseID: "aaa", Status: 200, Outcome: run.Unknown}},
			goodAccess, goodDecisions, false, "request ID"},
	}
	for name, tc := range tests {
		_, err := CheckLogs(tc.rs, tc.access, tc.decisions, tc.noDecisions)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %q does not mention %q", name, err, tc.want)
		}
		if strings.Contains(err.Error(), "aaa") || strings.Contains(err.Error(), "0a1b2c3d") {
			t.Errorf("%s: error %q names a case or the run", name, err)
		}
	}

	// A genuine zero: the firewall decided nothing about the run.
	cov, err = CheckLogs(sent, goodAccess, nil, true)
	if err != nil || cov.WithDecision != 0 || cov.WithAccess != 2 {
		t.Errorf("an empty decision log with the flag: %+v, %v", cov, err)
	}
	// Nothing sent: nothing to check.
	if cov, err := CheckLogs(sent[3:], nil, nil, false); err != nil || cov.Sent != 0 {
		t.Errorf("a run that sent nothing: %+v, %v", cov, err)
	}
}

// TestRunRequestIDsMatchCheckLogs ties CheckLogs to the request IDs Run
// sends: a run whose logs a target wrote passes.
func TestRunRequestIDsMatchCheckLogs(t *testing.T) {
	t.Parallel()
	s := startRemote(t, nil)
	target := remoteTarget(s)
	results, stop, err := Run(t.Context(), options(s, target, planFor(t, target, "query", 2)))
	if err != nil || stop != "" {
		t.Fatalf("run: %v, stop %q", err, stop)
	}
	access := map[string]records.Access{}
	decisions := map[string][]records.Decision{}
	for _, h := range s.all() {
		access[h.id] = records.Access{ID: h.id, Method: h.method}
		if h.kind == "case" {
			decisions[h.id] = []records.Decision{{ID: h.id, Action: "allow", Monitored: true, Rules: []string{"AEG-SQLI-001"}}}
		}
	}
	cov, err := CheckLogs(results, access, decisions, false)
	if err != nil || cov.Sent != 2 || cov.WithAccess != 2 || cov.WithDecision != 2 {
		t.Errorf("coverage %+v, %v", cov, err)
	}
	// Without the controls and health checks the access log proves nothing.
	for _, h := range s.all() {
		if h.kind != "case" {
			delete(access, h.id)
		}
	}
	if _, err := CheckLogs(results, access, decisions, false); err == nil {
		t.Error("an access log without the run's controls was accepted")
	}
}
